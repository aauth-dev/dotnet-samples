using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server.Governance;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Person;

/// <summary>
/// Conformance for the Person Server mapper (<c>MapAAuthPersonServer</c>) — the
/// one-call PS issuer (AAuth protocol §Agent Token Request, §PS-asserted access,
/// §PS-AS Federation). The mapper verifies the resource token, delegates the
/// identity + consent decision to <see cref="IIdentityClaimsAsserter"/>, mints
/// the auth token (three-party) or routes to an Access Server (four-party), and
/// packages the mission three-gate model over the mission primitives.
/// </summary>
public class PersonServerMapperTests
{
    private const string PsIssuer = "https://ps.test";
    private const string AsIssuer = "https://as.test";
    private const string ResourceUrl = "https://whoami.test";
    private const string AgentId = "aauth:demo@ap.example";
    private const string PsKid = "ps-1";
    private const string ResKid = "whoami-1";

    private static readonly AAuthKey ResourceKey = AAuthKey.Generate();

    // Build a PS host: real verification middleware + stub resource discovery +
    // the supplied asserter (default asserts a fixed sub).
    private static async Task<IHost> BuildHostAsync(IIdentityClaimsAsserter? asserter = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        var psKey = AAuthKey.Generate();
        builder.Services.AddSingleton(new AAuthVerifier { MaxAge = TimeSpan.FromSeconds(300) });
        builder.Services.AddSingleton(new TokenVerifier());
        builder.Services.AddSingleton(new MetadataClient(new HttpClient(new StubResourceHandler())));
        builder.Services.AddSingleton(new JwksClient(new HttpClient(new StubResourceHandler())));
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton(sp => new UpstreamTokenValidator(
            sp.GetRequiredService<MetadataClient>(), sp.GetRequiredService<JwksClient>()));
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddSingleton(asserter ?? new DefaultIdentityClaimsAsserter("user-42"));
        builder.Services.AddRouting();

        var app = builder.Build();
        app.MapAAuthPersonServer(new AAuthPersonServerOptions
        {
            Issuer = PsIssuer,
            SigningKeys = new System.Collections.Generic.Dictionary<string, AAuthKey> { [PsKid] = psKey },
            TrustedAccessServers = new[] { AsIssuer },
        });
        await app.StartAsync();
        return app;
    }

    private static HttpClient SignedAgentClient(IHost host, AAuthKey agentKey, string agentId)
    {
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = "agent-1",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        return new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
    }

    private static string ResourceToken(
        AAuthKey agentKey, string agentId, string audience, string scope = "whoami", MissionClaim? mission = null)
        => new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = agentId,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResKid,
            Scope = scope,
            Mission = mission,
        }.Build();

    private static JsonObject DecodePayload(string jwt)
    {
        var segments = jwt.Split('.');
        return (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;
    }

    [Fact(DisplayName = "§PS-asserted access — three-party mint binds the agent key and asserts the directed sub")]
    public async Task ThreeParty_MintsAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer) });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal(AgentId, (string?)payload["agent"]);
        Assert.Equal("user-42", (string?)payload["sub"]);
        Assert.Equal(AuthTokenBuilder.PersonDwk, (string?)payload["dwk"]);
        var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Error Responses — an auth token presented as carrier is refused (403 invalid_carrier_token)")]
    public async Task ThreeParty_RejectsAuthTokenAsCarrier()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();

        // Sign with an auth token (wrong carrier type), not an agent token.
        var authTokenAsCarrier = new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceUrl,
            Agent = AgentId,
            AgentConfirmationKey = agentKey,
            Key = AAuthKey.Generate(),
            KeyId = "x",
            Subject = "pairwise",
            Scope = "whoami",
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => authTokenAsCarrier)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        using var http = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = "irrelevant" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_carrier_token", (string?)body!["error"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Token Request — a missing resource_token is a 400")]
    public async Task ThreeParty_RejectsMissingResourceToken()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§PS-asserted access — a denying asserter yields 403 denied")]
    public async Task ThreeParty_DenyingAsserter_Forbidden()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Deny("not allowed")));
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer) });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)body!["error"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction — NeedsConsent parks a 202 poll; the host verdict resolves the mint")]
    public async Task ThreeParty_NeedsConsent_Parks202_ThenMints()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.NeedsConsent()));
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var post = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer) });

        Assert.Equal(HttpStatusCode.Accepted, post.StatusCode);
        var location = post.Headers.Location!.OriginalString;
        Assert.Contains("/pending/", location);

        // The host's interaction page resolves the verdict against the store.
        var store = (InMemoryPersonPendingStore)host.Services.GetRequiredService<IPersonPendingStore>();
        var id = location[(location.LastIndexOf('/') + 1)..];
        store.MarkAllowed(id, "user-99");

        using var poll = await http.GetAsync(location);
        Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);
        Assert.Equal("user-99", (string?)payload["sub"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Status Errors — a terminated mission is rejected (403 mission_terminated)")]
    public async Task Mission_Terminated_Rejected()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var missions = host.Services.GetRequiredService<IMissionStore>();
        await missions.SaveAsync(new StoredMission(s256, PsIssuer, AgentId, new byte[] { 1, 2, 3 }));
        await missions.SetStateAsync(s256, MissionState.Terminated);

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject
            {
                ["resource_token"] = ResourceToken(
                    agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256)),
            });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("mission_terminated", (string?)body!["error"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Token Request — an in-scope mission mints silently and records the grant")]
    public async Task Mission_InScope_Mints_AndLogsGrant()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Assert("user-42")));
        using var http = SignedAgentClient(host, agentKey, AgentId);

        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject
            {
                ["resource_token"] = ResourceToken(
                    agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256)),
            });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var payload = DecodePayload((string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.NotNull(payload["mission"]);

        // The grant was recorded so a repeat request resolves via prior consent.
        var log = host.Services.GetRequiredService<IMissionLog>();
        Assert.True(await log.HasPriorConsentAsync(s256, ResourceUrl, "whoami"));
        await host.StopAsync();
    }

    [Fact(DisplayName = "§PS-AS Federation — a resource token audienced to an untrusted AS is refused")]
    public async Task FourParty_UntrustedAccessServer_Refused()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = ResourceToken(agentKey, AgentId, "https://untrusted-as.test") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_access_server", (string?)body!["error"]);
        await host.StopAsync();
    }

    private sealed class StubAsserter : IIdentityClaimsAsserter
    {
        private readonly IdentityAssertion _assertion;
        public StubAsserter(IdentityAssertion assertion) => _assertion = assertion;
        public Task<IdentityAssertion> AssertAsync(
            IdentityAssertionRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(_assertion);
    }

    // Serves the resource's well-known metadata + JWKS so the SDK's
    // VerifyResourceTokenAsync resolves the resource's signing key in-process.
    private sealed class StubResourceHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            string json;
            if (path == "/.well-known/aauth-resource.json")
            {
                json = new JsonObject
                {
                    ["issuer"] = ResourceUrl,
                    ["jwks_uri"] = $"{ResourceUrl}/.well-known/jwks.json",
                }.ToJsonString();
            }
            else
            {
                var jwk = ResourceKey.ToPublicJwk();
                jwk["kid"] = ResKid;
                jwk["use"] = "sig";
                jwk["alg"] = AAuthKey.Algorithm;
                json = new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
