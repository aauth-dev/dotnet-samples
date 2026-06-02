using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Manual PS-to-AS exercise for the shipped <c>samples/MockAccessServer/</c>
/// sample (four-party / federated access). These stand in for the real PS
/// federation client (which arrives in a later phase): the test hand-signs
/// the PS-to-AS <c>POST /token</c> request with the <c>jwks_uri</c> scheme,
/// supplies the agent + resource tokens in the body, and asserts the AS
/// mints a verifiable <c>aa-auth+jwt</c> with <c>dwk = aauth-access.json</c>.
/// </summary>
public class MockAccessServerTests : IClassFixture<WebApplicationFactory<MockAccessServer.Entry>>, IDisposable
{
    private const string AsIssuer = "https://as.test";
    private const string PsIssuer = "https://ps.test";
    private const string ApIssuer = "https://ap.test";
    private const string ResourceUrl = "https://whoami.test";
    private const string AgentId = "aauth:demo@ap.test";

    private const string PsKid = "ps-1";
    private const string ApKid = "ap-1";
    private const string ResourceKid = "whoami-1";

    private static readonly AAuthKey PsKey = AAuthKey.Generate();
    private static readonly AAuthKey ApKey = AAuthKey.Generate();
    private static readonly AAuthKey ResourceKey = AAuthKey.Generate();

    private readonly WebApplicationFactory<MockAccessServer.Entry> _factory;

    public MockAccessServerTests(WebApplicationFactory<MockAccessServer.Entry> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", AsIssuer);
            b.UseSetting("MockAccessServer:TrustedPersonServers:0", PsIssuer);
            b.ConfigureServices(WireDiscovery);
        });
    }

    public void Dispose() => _factory.Dispose();

    [Fact]
    public async Task AccessMetadata_AdvertisesTokenEndpoint()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(AsIssuer),
        });

        var doc = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-access.json");

        Assert.NotNull(doc);
        Assert.Equal(AsIssuer, (string?)doc!["issuer"]);
        Assert.Equal($"{AsIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
        Assert.Equal($"{AsIssuer}/token", (string?)doc["token_endpoint"]);
    }

    [Fact]
    public async Task Token_MintsAccessAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = BuildAgentToken(agentKey);
        var resourceToken = BuildResourceToken(agentKey, audience: AsIssuer);

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var authTokenJwt = (string?)body!["auth_token"];
        Assert.False(string.IsNullOrEmpty(authTokenJwt));

        var segments = authTokenJwt!.Split('.');
        Assert.Equal(3, segments.Length);
        var header = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[0]))!;
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;

        Assert.Equal(AuthTokenBuilder.TokenType, (string?)header["typ"]);
        // The four-party discriminator: dwk = aauth-access.json (not aauth-person.json).
        Assert.Equal(AuthTokenBuilder.AccessDwk, (string?)payload["dwk"]);
        Assert.Equal(AsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal(AgentId, (string?)payload["agent"]);
        Assert.Equal("whoami", (string?)payload["scope"]);

        // cnf.jwk binds to the agent's key.
        var cnfJwk = payload["cnf"]?["jwk"] as JsonObject;
        Assert.NotNull(cnfJwk);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), AAuthKey.FromJwk(cnfJwk!).ComputeJwkThumbprint());
    }

    [Fact]
    public async Task Token_RejectsResourceTokenForDifferentAudience()
    {
        // A resource token whose aud is the PS (three-party) must NOT be
        // accepted by the AS — the AS only mints when aud = its own issuer.
        var agentKey = AAuthKey.Generate();
        var agentToken = BuildAgentToken(agentKey);
        var resourceToken = BuildResourceToken(agentKey, audience: PsIssuer);

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Token_RejectsUntrustedPersonServer()
    {
        // A request whose jwks_uri host is resolvable (signature verifies) but
        // not in the trusted-PS set is refused by the trust check (403).
        var agentKey = AAuthKey.Generate();
        var agentToken = BuildAgentToken(agentKey);
        var resourceToken = BuildResourceToken(agentKey, audience: AsIssuer);

        using var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri("https://other-ps.test/.well-known/jwks.json", PsKid)
            .WithInnerHandler(_factory.Server.CreateHandler())
            .Build();
        http.BaseAddress = new Uri(AsIssuer);

        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Token_GrantsElevatedScope_ForAdminAgent()
    {
        // The default stub policy grants whoami:admin to an admin agent
        // (the demo convention: agent id starts with "aauth:demo@").
        var agentKey = AAuthKey.Generate();
        var agentToken = BuildAgentToken(agentKey, AgentId);
        var resourceToken = BuildResourceToken(agentKey, audience: AsIssuer, agent: AgentId, scope: "whoami:admin");

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(
                ((string?)body!["auth_token"])!.Split('.')[1]))!;
        Assert.Equal("whoami:admin", (string?)payload["scope"]);
    }

    [Fact]
    public async Task Token_DeniesElevatedScope_ForNonAdminAgent()
    {
        // A non-admin agent requesting whoami:admin is denied by the stub
        // policy (no whoami-admin role) → 403 access_denied.
        const string GuestId = "aauth:guest@ap.test";
        var agentKey = AAuthKey.Generate();
        var agentToken = BuildAgentToken(agentKey, GuestId);
        var resourceToken = BuildResourceToken(agentKey, audience: AsIssuer, agent: GuestId, scope: "whoami:admin");

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("access_denied", (string?)body!["error"]);
    }

    // -- helpers ---------------------------------------------------------

    private HttpClient BuildPsSignedClient()
    {
        var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri($"{PsIssuer}/.well-known/jwks.json", PsKid)
            .WithInnerHandler(_factory.Server.CreateHandler())
            .Build();
        http.BaseAddress = new Uri(AsIssuer);
        return http;
    }

    private static string BuildAgentToken(AAuthKey agentKey) =>
        new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            KeyId = ApKid,
            Key = ApKey,                  // AP signs the token.
            ConfirmationKey = agentKey,   // bound to the agent's key (cnf.jwk).
            PersonServer = PsIssuer,
        }.Build();

    private static string BuildAgentToken(AAuthKey agentKey, string agent) =>
        new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = agent,
            KeyId = ApKid,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

    private static string BuildResourceToken(AAuthKey agentKey, string audience, string agent, string scope) =>
        new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResourceKid,
            Scope = scope,
        }.Build();

    private static string BuildResourceToken(AAuthKey agentKey, string audience) =>
        new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = AgentId,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResourceKid,
            Scope = "whoami",
        }.Build();

    /// <summary>
    /// Replace the AS's discovery clients so that, in-process, it can resolve:
    /// the PS's JWKS (HTTP-signature key), the AP's agent metadata + JWKS
    /// (agent-token verification), and the resource's metadata + JWKS
    /// (resource-token verification).
    /// </summary>
    private static void WireDiscovery(IServiceCollection services)
    {
        services.RemoveAll<MetadataClient>();
        services.RemoveAll<JwksClient>();
        services.AddSingleton(new MetadataClient(new HttpClient(new StubDiscoveryHandler())));
        services.AddSingleton(new JwksClient(new HttpClient(new StubDiscoveryHandler())));
    }

    private sealed class StubDiscoveryHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var key = $"{uri.Host}{uri.AbsolutePath}";
            string? json = key switch
            {
                "ps.test/.well-known/jwks.json" => Jwks(PsKey, PsKid),
                "other-ps.test/.well-known/jwks.json" => Jwks(PsKey, PsKid),
                "ap.test/.well-known/aauth-agent.json" => Metadata(ApIssuer),
                "ap.test/.well-known/jwks.json" => Jwks(ApKey, ApKid),
                "whoami.test/.well-known/aauth-resource.json" => Metadata(ResourceUrl),
                "whoami.test/.well-known/jwks.json" => Jwks(ResourceKey, ResourceKid),
                _ => null,
            };

            if (json is null)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }

        private static string Metadata(string issuer) => new JsonObject
        {
            ["issuer"] = issuer,
            ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
        }.ToJsonString();

        private static string Jwks(AAuthKey key, string kid)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }
}
