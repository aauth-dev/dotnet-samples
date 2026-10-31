using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server.Verification;
using AAuth.Tokens;
using AAuth.Testing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Issue #48: <c>MapAAuthResource()</c> must keep its own discovery documents
/// public. Agents fetch them with unsigned GETs (see <c>MetadataClient</c>),
/// while protected resource endpoints still require a valid AAuth request.
/// </summary>
public class MapAAuthResourceDiscoveryTests
{
    private const string ResourceId = "http://localhost:5000";

    [Fact(DisplayName = "MapAAuthResource serves aauth-resource.json and jwks.json to unsigned GETs")]
    public async Task DiscoveryDocuments_AreReachableWithoutSignature()
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();

        using var metadata = await client.GetAsync("/.well-known/aauth-resource.json");
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        var doc = JsonNode.Parse(await metadata.Content.ReadAsStringAsync())!.AsObject();
        Assert.Equal(ResourceId, (string?)doc["issuer"]);
        Assert.Equal($"{ResourceId}/.well-known/jwks.json", (string?)doc["jwks_uri"]);

        using var jwks = await client.GetAsync("/.well-known/jwks.json");
        Assert.Equal(HttpStatusCode.OK, jwks.StatusCode);
        var keys = JsonNode.Parse(await jwks.Content.ReadAsStringAsync())!["keys"]!.AsArray();
        Assert.Equal("res-1", (string?)Assert.Single(keys)!["kid"]);
    }

    [Fact(DisplayName = "MapAAuthResource still rejects unsigned requests to protected endpoints")]
    public async Task ProtectedEndpoint_StillRequiresSignature()
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/data");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("Signature-Error"));
    }

    // Only the SDK's own discovery documents are public. App routes under
    // /.well-known, look-alike paths and non-GET methods keep verification.
    [Theory(DisplayName = "MapAAuthResource keeps verification on every other path and method")]
    [InlineData("GET", "/.well-known/private")]
    [InlineData("GET", "/.well-known-data")]
    [InlineData("POST", "/.well-known/aauth-resource.json")]
    [InlineData("HEAD", "/.well-known/aauth-resource.json")]
    public async Task OtherPathsAndMethods_StillRequireSignature(string method, string path)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();

        using var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("Signature-Error"));
    }

    [Fact(DisplayName = "MapAAuthResource without signing keys publishes metadata only, and jwks.json stays protected")]
    public async Task WithoutSigningKeys_OnlyMetadataIsPublic()
    {
        await using var app = await StartAsync(withKeys: false);
        using var client = app.GetTestClient();

        using var metadata = await client.GetAsync("/.well-known/aauth-resource.json");
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        using var jwks = await client.GetAsync("/.well-known/jwks.json");
        Assert.Equal(HttpStatusCode.Unauthorized, jwks.StatusCode);
    }

    // The discovery exemption must not change what happens to signed requests:
    // a valid agent-token request still goes through verification and reaches
    // the protected endpoint.
    [Fact(DisplayName = "MapAAuthResource still verifies and admits a validly signed agent request")]
    public async Task SignedAgentRequest_IsVerifiedAndAdmitted()
    {
        var apKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        await using var agentProvider = await StartAgentProviderAsync(apKey);
        await using var app = await StartAsync(
            configureServices: services =>
            {
                services.AddSingleton(new MetadataClient(agentProvider.GetTestClient(), policy: TestEgress.Policy,
                    transportContract: AAuthTransportContract.InProcessOnly));
                services.AddSingleton(new JwksClient(agentProvider.GetTestClient(), policy: TestEgress.Policy,
                    transportContract: AAuthTransportContract.InProcessOnly));
            },
            configurePipeline: options => options.AccessMode = AAuthAccessMode.IdentityOnly);

        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = AgentProviderId,
            Subject = "aauth:test@localhost",
            Key = apKey,
            KeyId = "ap-1",
            ConfirmationKey = agentKey,
        }.BuildAsync();
        using var client = new AAuthClientBuilder(agentKey).UseJwt(agentToken)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();

        using var response = await client.GetAsync($"{ResourceId}/whoami");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("aauth:test@localhost", await response.Content.ReadAsStringAsync());
    }

    // The exemption follows the handler that runs, not the request path. A URL
    // rewrite after MapAAuthResource must not carry the discovery exemption to a
    // protected endpoint.
    [Fact(DisplayName = "MapAAuthResource exemption cannot be redirected to a protected endpoint by a URL rewrite")]
    public async Task RewrittenDiscoveryUrl_DoesNotBypassVerification()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthResource(options =>
        {
            options.Issuer = ResourceId;
            options.EgressPolicy = TestEgress.Policy;
            options.SigningKeys.Add("res-1", AAuthKey.Generate());
        });
        await using var app = builder.Build();
        app.MapAAuthResource();
        app.UseRewriter(new RewriteOptions().AddRewrite(
            @"^\.well-known/aauth-resource\.json$", "data", skipRemainingRules: true));
        app.UseRouting();
        app.MapGet("/data", () => "secret");
        await app.StartAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/.well-known/aauth-resource.json");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("secret", await response.Content.ReadAsStringAsync());
    }

    private const string AgentProviderId = "http://localhost:5555";

    private static async Task<WebApplication> StartAgentProviderAsync(AAuthKey apKey)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = AgentProviderId,
            jwks_uri = $"{AgentProviderId}/.well-known/jwks.json",
        }));
        app.MapGet("/.well-known/jwks.json", () =>
        {
            var jwk = apKey.ToPublicJwk();
            jwk["kid"] = "ap-1";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });
        await app.StartAsync();
        return app;
    }

    private static async Task<WebApplication> StartAsync(bool withKeys = true,
        Action<IServiceCollection>? configureServices = null,
        Action<AAuthResourcePipelineOptions>? configurePipeline = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthResource(options =>
        {
            options.Issuer = ResourceId;
            options.EgressPolicy = TestEgress.Policy;
            if (withKeys)
                options.SigningKeys.Add("res-1", AAuthKey.Generate());
        });
        configureServices?.Invoke(builder.Services);
        var app = builder.Build();
        app.MapAAuthResource(configurePipeline);
        app.MapGet("/whoami", (HttpContext context) => context.GetAAuthVerification()!.Agent ?? context.GetAAuthVerification()!.Subject);
        app.MapGet("/data", () => "secret");
        app.MapGet("/.well-known/private", () => "secret");
        app.MapGet("/.well-known-data", () => "secret");
        await app.StartAsync();
        return app;
    }
}
