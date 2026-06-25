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

    // Build an auth token to present as `upstream_token` in a call-chaining
    // request. `dwk` selects the issuer role the PS mission gate sees:
    // aauth-access.json ⇒ an AS (four-party), aauth-person.json ⇒ a PS
    // (three-party). `aud` MUST equal the intermediary agent token's `iss`
    // (= https://ap.example here) per §Upstream Token Verification step 3.
    private static string UpstreamToken(string issuer, string dwk, MissionClaim? mission = null)
        => new AuthTokenBuilder
        {
            Issuer = issuer,
            Dwk = dwk,
            Audience = "https://ap.example",
            Agent = "aauth:upstream-caller@ap.example",
            AgentConfirmationKey = AAuthKey.Generate(),
            Key = ResourceKey,
            KeyId = ResKid,
            Scope = "data.read",
            Subject = "user-1",
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

    [Fact(DisplayName = "§Sub-Agents — parent-mediated three-party mint binds the SUB-AGENT key and nests act")]
    public async Task SubAgent_ParentMediated_BindsSubAgentKey_NestsAct()
    {
        const string ParentId = "aauth:demo@ap.example";
        const string SubId = "aauth:demo+w1@ap.example";
        var parentKey = AAuthKey.Generate();
        var subKey = AAuthKey.Generate();

        // Sub-agent token: signed by the AP key the stub serves (ResourceKey/ResKid),
        // cnf bound to the sub-agent key, carrying parent_agent.
        var subagentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = SubId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = subKey,
            ParentAgent = ParentId,
            PersonServer = PsIssuer,
        }.Build();

        // Resource token the SUB-AGENT obtained (bound to its own key).
        var resourceToken = ResourceToken(subKey, SubId, PsIssuer);

        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, parentKey, ParentId); // parent signs

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = resourceToken,
            ["subagent_token"] = subagentToken,
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);

        // Auth token binds to the sub-agent's identity + key.
        Assert.Equal(SubId, (string?)payload["agent"]);
        var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
        Assert.Equal(subKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());

        // Sub-agent is the top-level agent; act names the parent (immediate upstream).
        // act = { agent: parent } with no deeper node (§Delegation Chain).
        var act = (JsonObject)payload["act"]!;
        Assert.Equal(ParentId, (string?)act["agent"]);
        Assert.Null(act["act"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Token Request — the PS flows prompt and capabilities to the asserter")]
    public async Task TokenRequest_PromptAndCapabilities_ReachAsserter()
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer),
            ["prompt"] = "consent",
            ["capabilities"] = new JsonArray("interaction", "payment"),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        Assert.NotNull(asserter.Last);
        Assert.Equal("consent", asserter.Last!.Prompt);
        Assert.NotNull(asserter.Last.Capabilities);
        Assert.Contains("interaction", asserter.Last.Capabilities!);
        Assert.Contains("payment", asserter.Last.Capabilities!);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Single-Level Depth — the PS rejects a request signed by a sub-agent")]
    public async Task SubAgent_DirectRequest_Rejected()
    {
        const string ParentId = "aauth:demo@ap.example";
        const string SubId = "aauth:demo+w1@ap.example";
        var subKey = AAuthKey.Generate();

        // A sub-agent token used to SIGN the request directly (not allowed).
        var subagentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = SubId,
            KeyId = "agent-1",
            Key = subKey,
            ParentAgent = ParentId,
            PersonServer = PsIssuer,
        }.Build();

        using var host = await BuildHostAsync();
        var signing = new AAuthSigningHandler(subKey, () => subagentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        using var http = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = ResourceToken(subKey, SubId, PsIssuer) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);

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

    [Fact(DisplayName = "§Token Endpoint Error Codes — an unverifiable resource_token is a 400 invalid_resource_token (not a 401)")]
    public async Task ThreeParty_RejectsInvalidResourceToken_With400()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        // A resource token carrying the published kid but signed with a different
        // key — the PS resolves the genuine JWKS key and the signature check fails.
        var forged = new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = PsIssuer,
            Agent = AgentId,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = AAuthKey.Generate(),
            KeyId = ResKid,
            Scope = "whoami",
        }.Build();

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = forged });

        // §Token Endpoint Error Codes lists invalid_resource_token / expired_resource_token
        // as 400 (a bad token parameter in the body). §Authentication Errors reserves 401
        // for request-signature failures carrying a Signature-Error header — the agent's
        // request signature is valid here, so a 401 would mismatch the spec.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
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

    [Fact(DisplayName = "§Call Chaining — four-party upstream (AS-issued) without a mission is rejected")]
    public async Task CallChaining_FourPartyUpstream_NoMission_Rejected()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer),
            ["upstream_token"] = UpstreamToken(AsIssuer, AuthTokenBuilder.AccessDwk),
        });

        // The PS MUST require a mission to stay in the loop for four-party chains.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Contains("mission", (string?)body["detail"], StringComparison.OrdinalIgnoreCase);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Call Chaining — three-party upstream (PS-issued) without a mission is allowed")]
    public async Task CallChaining_ThreePartyUpstream_NoMission_Allowed()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer),
            ["upstream_token"] = UpstreamToken(PsIssuer, AuthTokenBuilder.PersonDwk),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);
        // The downstream act records the upstream delegator, proving the chain was accepted.
        var act = (JsonObject)payload["act"]!;
        Assert.Equal("aauth:upstream-caller@ap.example", (string?)act["agent"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Call Chaining — four-party upstream (AS-issued) with a mission is allowed")]
    public async Task CallChaining_FourPartyUpstream_WithMission_Allowed()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync();
        using var http = SignedAgentClient(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer),
            // A mission.approver anchors the four-party chain to a PS — the gate passes.
            ["upstream_token"] = UpstreamToken(AsIssuer, AuthTokenBuilder.AccessDwk, new MissionClaim(PsIssuer, s256)),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
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

    // Captures the request the host hands the asserter so tests can assert that
    // prompt/capabilities flowed from the token-request body to the decision seam.
    private sealed class CapturingAsserter : IIdentityClaimsAsserter
    {
        public IdentityAssertionRequest? Last { get; private set; }
        public Task<IdentityAssertion> AssertAsync(
            IdentityAssertionRequest request, CancellationToken cancellationToken = default)
        {
            Last = request;
            return Task.FromResult(IdentityAssertion.Assert("user-42"));
        }
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
            else if (path == "/.well-known/aauth-agent.json")
            {
                // AP metadata for sub-agent (subagent_token) verification. The
                // jwks_uri resolves (via the else branch below) to the shared
                // ResourceKey JWKS, so a sub-agent token signed with ResourceKey
                // verifies. issuer must match the fetch origin (host-binding).
                json = new JsonObject
                {
                    ["issuer"] = "https://ap.example",
                    ["jwks_uri"] = "https://ap.example/.well-known/jwks.json",
                }.ToJsonString();
            }
            else if (path == "/.well-known/aauth-person.json" || path == "/.well-known/aauth-access.json")
            {
                // Upstream-issuer metadata for call-chaining (upstream_token)
                // verification. The issuer is the fetch origin (host-binding), and
                // the jwks_uri resolves (via the else branch) to the shared
                // ResourceKey JWKS, so an upstream token signed with ResourceKey
                // verifies regardless of whether the issuer role is PS or AS.
                var authority = request.RequestUri!.GetLeftPart(UriPartial.Authority);
                json = new JsonObject
                {
                    ["issuer"] = authority,
                    ["jwks_uri"] = $"{authority}/.well-known/jwks.json",
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
