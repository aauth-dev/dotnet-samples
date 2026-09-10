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
using AAuth.Headers;
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

    private sealed class PublicDns : IAAuthDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    // Build a PS host: real verification middleware + stub resource discovery +
    // the supplied asserter (default asserts a fixed sub) and optional mission
    // consent seam (default = the conservative DefaultMissionTokenConsent).
    private static async Task<IHost> BuildHostAsync(
        IIdentityClaimsAsserter? asserter = null, IMissionTokenConsent? consent = null, bool demoResource = false)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        var psKey = AAuthKey.Generate();
        builder.Services.AddSingleton(new AAuthVerifier { MaxAge = TimeSpan.FromSeconds(300) });
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = TestEgress.Policy });
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(new StubResourceHandler())));
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(new StubResourceHandler())));
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton(sp => new UpstreamTokenValidator(
            sp.GetRequiredService<MetadataClient>(), sp.GetRequiredService<JwksClient>()));
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddSingleton(asserter ?? new DefaultIdentityClaimsAsserter("user-42"));
        if (consent is not null)
        {
            builder.Services.AddSingleton<IMissionTokenConsent>(consent);
        }
        builder.Services.AddRouting();

        var app = builder.Build();
        app.MapAAuthPersonServer(new AAuthPersonServerOptions
        {
            EgressPolicy = new AAuthEgressPolicy(dnsResolver: new PublicDns()),
            Issuer = PsIssuer,
            SigningKeys = new System.Collections.Generic.Dictionary<string, IAAuthKey> { [PsKid] = psKey },
            TrustedAccessServers = new[] { AsIssuer },
            ResourceInteractionSessions = demoResource ? new AAuth.Server.BrowserConsentSessions("resource-tests", "demo-person", isolatedDemoAccess: _ => true) : null,
        });
        await app.StartAsync();
        await app.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", PsIssuer, AgentId, new byte[] { 1, 2, 3 }));
        return app;
    }

    private static HttpClient SignedAgentClient(IHost host, AAuthKey agentKey, string agentId)
    {
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        return new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
    }

    private static string ResourceToken(
        AAuthKey agentKey, string agentId, string audience, string scope = "whoami", MissionClaim? mission = null, string? account = null)
        => new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = agentId,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResKid,
            Scope = scope,
            Mission = mission,
            Account = account,
        }.Build();

    // Build an auth token to present as `upstream_token` in a call-chaining
    // request. `dwk` selects the issuer role the PS mission gate sees:
    // aauth-access.json ⇒ an AS (four-party), aauth-person.json ⇒ a PS
    // (three-party). `aud` MUST equal the intermediary agent token's `iss`
    // (= https://ap.example here) per §Upstream Token Verification step 3.
    private static string UpstreamToken(string issuer, string dwk, MissionClaim? mission = null)
        => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
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
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
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

    [Fact]
    public async Task TokenRequest_MissingResourceToken_ReturnsProblemDetails()
    {
        using var host = await BuildHostAsync();
        using var client = SignedAgentClient(host, AAuthKey.Generate(), AgentId);
        using var response = await client.PostAsJsonAsync("/token", new JsonObject());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Equal("missing resource_token", (string?)body["detail"]);
        Assert.False(body.ContainsKey("error_description"));
        Assert.False(response.Headers.Contains("Signature-Error"));
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
            EgressPolicy = TestEgress.Policy,
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
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = SubId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = subKey,
            ParentAgent = ParentId,
            PersonServer = PsIssuer,
        }.Build();

        using var host = await BuildHostAsync();
        var signing = new AAuthSigningHandler(subKey, () => subagentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

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
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
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
        using var http = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = "irrelevant" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("Signature-Error"));

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
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
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

    [Theory]
    [InlineData("GET", false)]
    [InlineData("POST", false)]
    [InlineData("DELETE", false)]
    [InlineData("GET", true)]
    [InlineData("POST", true)]
    [InlineData("DELETE", true)]
    public async Task Pending_RejectsForeignOwnerAndChangedKey(string method, bool sameSubject)
    {
        var agentKey = AAuthKey.Generate();
        var consent = new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?"));
        using var host = await BuildHostAsync(consent: consent);
        using var owner = SignedAgentClient(host, agentKey, AgentId);
        using var first = await owner.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer,
                mission: new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
        });
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        using var attacker = SignedAgentClient(host, AAuthKey.Generate(),
            sameSubject ? AgentId : "aauth:attacker@ap.example");
        using var request = new HttpRequestMessage(new HttpMethod(method), first.Headers.Location);
        if (method == "POST")
            request.Content = JsonContent.Create(new { action = "clarification_response", clarification_response = "approve" });
        using var response = await attacker.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var poll = await owner.GetAsync(first.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
        await host.StopAsync();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("unknown")]
    [InlineData("updated_request")]
    public async Task Clarification_RejectsMissingUnknownAndMismatchedAction(string? action)
    {
        var key = AAuthKey.Generate();
        using var host = await BuildHostAsync(consent: new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?")));
        using var client = SignedAgentClient(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(key, AgentId, PsIssuer,
                mission: new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
        });
        using var response = await client.PostAsJsonAsync(initial.Headers.Location,
            new JsonObject { ["action"] = action, ["clarification_response"] = "approve" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var poll = await client.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("malformed")]
    [InlineData("agent")]
    [InlineData("key")]
    [InlineData("audience")]
    public async Task Clarification_ReplacementIsVerifiedAndChangesConsentScope(string variant)
    {
        var key = AAuthKey.Generate();
        var mission = new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        MissionTokenConsentContext? reviewed = null;
        using var host = await BuildHostAsync(consent: new StubMissionConsent(context =>
        {
            reviewed = context;
            return context.Scope == "read" ? MissionTokenConsentDecision.Grant() : MissionTokenConsentDecision.Clarify("Narrow scope?");
        }));
        using var client = SignedAgentClient(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(key, AgentId, PsIssuer, "read write", mission),
        });
        var replacement = variant == "malformed" ? "not-a-jwt" : ResourceToken(
            variant == "key" ? AAuthKey.Generate() : key, variant == "agent" ? "aauth:other@ap.example" : AgentId,
            variant == "audience" ? AsIssuer : PsIssuer, "read", mission);
        using var response = await client.PostAsJsonAsync(initial.Headers.Location, new JsonObject
        {
            ["action"] = "updated_request", ["resource_token"] = replacement,
        });
        Assert.Equal(variant == "valid" ? HttpStatusCode.NoContent : HttpStatusCode.BadRequest, response.StatusCode);
        using var poll = await client.GetAsync(initial.Headers.Location);
        if (variant == "valid")
        {
            Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
            Assert.Equal("read", reviewed!.Scope);
            var token = (await poll.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!.GetValue<string>();
            Assert.Equal("read", DecodePayload(token)["scope"]!.GetValue<string>());
            using var again = await client.GetAsync(initial.Headers.Location);
            Assert.Equal(HttpStatusCode.Gone, again.StatusCode);
        }
        else Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pending_TerminalDeliveryIsAtomicAndDecisionCannotReverse(bool allow)
    {
        var key = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.NeedsConsent()));
        using var client = SignedAgentClient(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = ResourceToken(key, AgentId, PsIssuer),
        });
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var id = initial.Headers.Location!.ToString().Split('/')[^1];
        if (allow) { store.MarkAllowed(id, "user"); store.MarkDenied(id, "reversal"); }
        else { store.MarkDenied(id, "denied"); store.MarkAllowed(id, "reversal"); }
        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => client.GetAsync(initial.Headers.Location)));
        Assert.Single(responses, response => response.StatusCode == (allow ? HttpStatusCode.OK : HttpStatusCode.Forbidden));
        Assert.Equal(11, responses.Count(response => response.StatusCode == HttpStatusCode.Gone));
        foreach (var response in responses) response.Dispose();
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

    [Fact]
    public async Task AccountMission_IdentityDenialCannotCreatePriorConsent()
    {
        var reviews = 0;
        var key = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Deny("denied identity")),
            new StubMissionConsent(_ => { reviews++; return MissionTokenConsentDecision.Grant(); }));
        using var client = SignedAgentClient(host, key, AgentId);
        const string hash = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/token", new
            {
                resource_token = ResourceToken(key, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, hash), account: "personal"),
            });
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        var log = host.Services.GetRequiredService<IMissionLog>();
        Assert.DoesNotContain(await log.ReadAsync(hash), entry => entry.Granted == true);
        Assert.Equal(2, reviews);
    }

    [Fact(DisplayName = "§Agent Token Request — an in-scope mission mints silently and records the grant")]
    public async Task Mission_InScope_Mints_AndLogsGrant()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(
            new StubAsserter(IdentityAssertion.Assert("user-42")),
            new StubMissionConsent(_ => MissionTokenConsentDecision.Grant()));
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
        Assert.True(await log.HasPriorConsentAsync(s256, ResourceUrl, "whoami",
            agentId: AgentId, agentKeyThumbprint: agentKey.ComputeJwkThumbprint()));
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Clarification Chat — out-of-scope clarify round, then a grant logged OutOfScope")]
    public async Task Mission_OutOfScope_ClarifyThenGrant()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Gate ⇒ ask a question; once the agent answers, grant.
        var consent = new StubMissionConsent(ctx => ctx.ClarificationHistory.Count == 0
            ? MissionTokenConsentDecision.Clarify("Why do you need this scope?")
            : MissionTokenConsentDecision.Grant());
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Assert("user-42")), consent);
        using var http = SignedAgentClient(host, agentKey, AgentId);

        var resourceToken = ResourceToken(agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256));
        using var first = await http.PostAsJsonAsync("/token", new JsonObject { ["resource_token"] = resourceToken });

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal($"requirement={ClarificationRequirement.RequirementType}",
            first.Headers.GetValues(AAuth.Headers.AAuthRequirementHeader.Name).Single());
        var pendingUrl = first.Headers.Location!.ToString();
        var firstBody = await first.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("Why do you need this scope?", (string?)firstBody!["clarification"]);

        // Answer the clarification, then resume polling.
        using var answer = await http.PostAsJsonAsync(pendingUrl,
            new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = "It is required to read the resource." });
        Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);

        using var poll = await http.GetAsync(pendingUrl);
        Assert.True(poll.IsSuccessStatusCode,
            $"Status={(int)poll.StatusCode} {await poll.Content.ReadAsStringAsync()}");
        var token = (string)(await poll.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!;
        Assert.False(string.IsNullOrEmpty(token));

        var log = host.Services.GetRequiredService<IMissionLog>();
        var entries = await log.ReadAsync(s256);
        Assert.Contains(entries, e => e.Kind == MissionLogEntryKind.Clarification);
        var tokenEntry = entries.Last(e => e.Kind == MissionLogEntryKind.Token);
        Assert.Equal(true, tokenEntry.Granted);
        Assert.Equal("OutOfScope", tokenEntry.Detail);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Token Request — an out-of-scope mission the seam denies returns 403 + logs OutOfScope")]
    public async Task Mission_OutOfScope_Deny()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Gate ⇒ interactive hold; the poll denies.
        var consent = new StubMissionConsent(ctx => ctx.Stage == MissionTokenConsentStage.Gate
            ? MissionTokenConsentDecision.Interact()
            : MissionTokenConsentDecision.Deny("not allowed"));
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Assert("user-42")), consent);
        using var http = SignedAgentClient(host, agentKey, AgentId);

        var resourceToken = ResourceToken(agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256));
        using var first = await http.PostAsJsonAsync("/token", new JsonObject { ["resource_token"] = resourceToken });
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        var pendingUrl = first.Headers.Location!.ToString();

        using var poll = await http.GetAsync(pendingUrl);
        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)body!["error"]);

        var log = host.Services.GetRequiredService<IMissionLog>();
        var tokenEntry = (await log.ReadAsync(s256)).Last(e => e.Kind == MissionLogEntryKind.Token);
        Assert.Equal(false, tokenEntry.Granted);
        Assert.Equal("OutOfScope", tokenEntry.Detail);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Response to Clarification — a withdrawn request is 410 and logs a cancellation")]
    public async Task Mission_Clarification_Withdraw()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var consent = new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?"));
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Assert("user-42")), consent);
        using var http = SignedAgentClient(host, agentKey, AgentId);

        var resourceToken = ResourceToken(agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256));
        using var first = await http.PostAsJsonAsync("/token", new JsonObject { ["resource_token"] = resourceToken });
        var pendingUrl = first.Headers.Location!.ToString();

        using var withdraw = await http.DeleteAsync(pendingUrl);
        Assert.Equal(HttpStatusCode.NoContent, withdraw.StatusCode);

        using var poll = await http.GetAsync(pendingUrl);
        Assert.Equal(HttpStatusCode.Gone, poll.StatusCode);

        var log = host.Services.GetRequiredService<IMissionLog>();
        var entries = await log.ReadAsync(s256);
        Assert.Contains(entries, e => e.Kind == MissionLogEntryKind.Clarification && e.Detail == "cancelled");
        Assert.DoesNotContain(entries, e => e.Kind == MissionLogEntryKind.Token && e.Granted == true);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Response to Clarification — a foreign agent cannot answer or withdraw another's pending")]
    public async Task Mission_Clarification_RejectsForeignAgent()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var consent = new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?"));
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Assert("user-42")), consent);
        using var owner = SignedAgentClient(host, agentKey, AgentId);

        var resourceToken = ResourceToken(agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256));
        using var first = await owner.PostAsJsonAsync("/token", new JsonObject { ["resource_token"] = resourceToken });
        var pendingUrl = first.Headers.Location!.ToString();

        // A different, validly-signed agent must not touch the owner's pending entry.
        using var attacker = SignedAgentClient(host, AAuthKey.Generate(), "aauth:attacker@ap.example");
        using var foreignPost = await attacker.PostAsJsonAsync(pendingUrl,
            new JsonObject { ["clarification_response"] = "let me in" });
        Assert.Equal(HttpStatusCode.NotFound, foreignPost.StatusCode);
        using var foreignDelete = await attacker.DeleteAsync(pendingUrl);
        Assert.Equal(HttpStatusCode.NotFound, foreignDelete.StatusCode);

        // The owner's own clarification round still works.
        using var ownerPost = await owner.PostAsJsonAsync(pendingUrl,
            new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = "for the user's records" });
        Assert.Equal(HttpStatusCode.NoContent, ownerPost.StatusCode);
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
            ["resource_token"] = ResourceToken(agentKey, AgentId, PsIssuer, mission: new MissionClaim(PsIssuer, s256)),
            // A mission.approver anchors the four-party chain to a PS — the gate passes.
            ["upstream_token"] = UpstreamToken(AsIssuer, AuthTokenBuilder.AccessDwk, new MissionClaim(PsIssuer, s256)),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Clarification_UpstreamMissionCannotBeStrippedOrChanged(bool changed)
    {
        var key = AAuthKey.Generate();
        var mission = new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        using var host = await BuildHostAsync(consent: new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?")));
        var missions = host.Services.GetRequiredService<IMissionStore>();
        await missions.SaveAsync(new StoredMission(mission.S256, PsIssuer, "aauth:upstream-caller@ap.example", new byte[] { 1 }));
        using var client = SignedAgentClient(host, key, AgentId);
        var original = ResourceToken(key, AgentId, PsIssuer, mission: mission);
        using var initial = await client.PostAsJsonAsync("/token", new
        {
            resource_token = original,
            upstream_token = UpstreamToken(AsIssuer, AuthTokenBuilder.AccessDwk, mission),
        });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var id = initial.Headers.Location!.ToString().Split('/')[^1];
        var entry = store.Get(id)!;
        using var replacement = await client.PostAsJsonAsync(initial.Headers.Location, new
        {
            action = "updated_request",
            resource_token = ResourceToken(key, AgentId, PsIssuer, mission: changed
                ? new MissionClaim(PsIssuer, "eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null),
        });
        Assert.Equal(HttpStatusCode.BadRequest, replacement.StatusCode);
        Assert.Equal(original, entry.ResourceToken);
        Assert.Equal(mission, entry.Mission);
        Assert.True(entry.MissionGate);
        Assert.Equal(0, entry.ClarificationRounds);
        await missions.SetStateAsync(mission.S256, MissionState.Terminated);
        store.MarkAllowed(id, "user-42");
        using var poll = await client.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        Assert.Equal("mission_terminated", (string?)(await poll.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Theory]
    [InlineData("unknown", false)]
    [InlineData("foreign-owner", false)]
    [InlineData("stored-approver", false)]
    [InlineData("unknown", true)]
    [InlineData("foreign-owner", true)]
    [InlineData("stored-approver", true)]
    public async Task Mission_InvalidApprovalNeverReachesConsent(string variant, bool interaction)
    {
        var key = AAuthKey.Generate();
        var reviews = 0;
        using var host = await BuildHostAsync(consent: new StubMissionConsent(_ =>
        {
            reviews++;
            return MissionTokenConsentDecision.Grant();
        }));
        var mission = new MissionClaim(PsIssuer, "eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        if (variant != "unknown")
            await host.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
                mission.S256, variant == "stored-approver" ? "https://other-ps.test" : PsIssuer,
                variant == "foreign-owner" ? "aauth:other@ap.example" : AgentId, new byte[] { 1 }));
        using var client = SignedAgentClient(host, key, AgentId);
        var resourceToken = ResourceToken(key, AgentId, PsIssuer, mission: mission);
        if (interaction)
        {
            var payload = DecodePayload(resourceToken);
            payload["interaction"] = new JsonObject { ["url"] = ResourceUrl + "/permission", ["code"] = "ABCDEFGH" };
            resourceToken = JwtWriter.SignCompact(TokenVerifier.DecodeJsonSegment(resourceToken.Split('.')[0], "header"), payload, ResourceKey);
        }
        using var response = await client.PostAsJsonAsync("/token", new
        {
            resource_token = resourceToken,
        });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, reviews);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Mission_ParentConsentIdentitySurvivesClarification(bool deferred)
    {
        var parentKey = AAuthKey.Generate();
        var childKey = AAuthKey.Generate();
        const string child = "aauth:demo+worker@ap.example";
        var mission = new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter, new StubMissionConsent(context =>
            deferred && context.ClarificationHistory.Count == 0
                ? MissionTokenConsentDecision.Clarify("Why?") : MissionTokenConsentDecision.Grant()));
        await host.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(mission.S256, PsIssuer, AgentId, new byte[] { 1 }));
        var childToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = "https://ap.example", Subject = child,
            KeyId = ResKid, Key = ResourceKey, ConfirmationKey = childKey, ParentAgent = AgentId, PersonServer = PsIssuer,
        }.Build();
        using var client = SignedAgentClient(host, parentKey, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", new
        {
            resource_token = ResourceToken(childKey, child, PsIssuer, mission: mission), subagent_token = childToken,
        });
        HttpResponseMessage result = initial;
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            using var answer = await client.PostAsJsonAsync(initial.Headers.Location, new
            {
                action = "clarification_response", clarification_response = "Requested by the parent.",
            });
            Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
            result = await client.GetAsync(initial.Headers.Location);
        }
        using (result)
        {
            Assert.Equal(HttpStatusCode.OK, result.StatusCode);
            Assert.Equal(AgentId, asserter.Last!.AgentId);
            var token = (string)(await result.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!;
            var payload = DecodePayload(token);
            Assert.Equal(child, (string?)payload["agent"]);
            Assert.Equal(childKey.ComputeJwkThumbprint(), AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!).ComputeJwkThumbprint());
        }
    }

    [Fact]
    public async Task ResourceInteractionPrecedesIdentityAndConsent()
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var client = SignedAgentClient(host, key, AgentId);
        var original = ResourceToken(key, AgentId, PsIssuer);
        var payload = DecodePayload(original);
        payload["interaction"] = new JsonObject { ["url"] = ResourceUrl + "/permission", ["code"] = "ABCDEFGH" };
        var header = TokenVerifier.DecodeJsonSegment(original.Split('.')[0], "header");
        var token = JwtWriter.SignCompact(header, payload, ResourceKey);
        using var response = await client.PostAsJsonAsync("/token", new { resource_token = token });
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Null(asserter.Last);
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var entry = store.Get(response.Headers.Location!.ToString().Split('/')[^1])!;
        Assert.True(JsonNode.DeepEquals(payload, entry.ResourceContext));
        store.MarkAllowed(entry.Id, "forged approval");
        using var poll = await client.GetAsync(response.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
        Assert.Null(asserter.Last);
    }

    [Theory]
    [InlineData(null, 200, null)]
    [InlineData("access_denied", 403, "denied")]
    [InlineData("user_abandoned", 403, "abandoned")]
    [InlineData("interaction_expired", 408, "expired")]
    [InlineData("server_error", 500, "server_error")]
    [InlineData("", 500, "server_error")]
    public async Task ResourceInteractionCallbackIsBoundAndPrecedesConsent(string? error, int expectedStatus, string? expectedError)
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter, demoResource: true);
        using var agent = SignedAgentClient(host, key, AgentId);
        var token = new ResourceTokenBuilder
        {
            Issuer = ResourceUrl, Audience = PsIssuer, Agent = AgentId, AgentJkt = key.ComputeJwkThumbprint(),
            Key = ResourceKey, KeyId = ResKid, Scope = "whoami", ScopeDescriptions = TestScopeDefinitions.Resource,
            Account = "work", Interaction = new Interaction(ResourceUrl + "/permission", "ABCDEFGH"),
        }.Build();
        using var initial = await agent.PostAsJsonAsync("/token", new { resource_token = token });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Null(asserter.Last);
        var requirement = Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues(AAuthRequirementHeader.Name).Single()))!;
        var cookies = new System.Collections.Generic.Dictionary<string, string>();
        using var browser = host.GetTestClient();
        browser.BaseAddress = new Uri(PsIssuer);
        async Task<HttpResponseMessage> Send(HttpMethod method, string url, object? form = null)
        {
            using var request = new HttpRequestMessage(method, url);
            if (cookies.Count > 0) request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies.Values));
            if (form is System.Collections.Generic.Dictionary<string, string> fields) request.Content = new FormUrlEncodedContent(fields);
            var response = await browser.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
                foreach (var value in values) { var cookie = value.Split(';')[0]; cookies[cookie.Split('=')[0]] = cookie; }
            return response;
        }
        using var login = await Send(HttpMethod.Get, requirement.BuildUserUrl());
        var loginHtml = await login.Content.ReadAsStringAsync();
        using var signIn = await Send(HttpMethod.Post, requirement.BuildUserUrl(), new System.Collections.Generic.Dictionary<string, string>
        { ["sign_in"] = "demo", ["csrf"] = AAuth.Testing.TestConsentBrowser.Field(loginHtml, "csrf") });
        using var enter = await Send(HttpMethod.Get, signIn.Headers.Location!.ToString());
        using var interstitial = await Send(HttpMethod.Get, enter.Headers.Location!.ToString());
        var html = await interstitial.Content.ReadAsStringAsync();
        using var departure = await Send(HttpMethod.Post, "/interaction/resource/continue", new System.Collections.Generic.Dictionary<string, string>
        {
            ["session"] = AAuth.Testing.TestConsentBrowser.Field(html, "session"),
            ["csrf"] = AAuth.Testing.TestConsentBrowser.Field(html, "csrf"),
        });
        Assert.Equal(HttpStatusCode.Redirect, departure.StatusCode);
        Assert.Null(asserter.Last);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(departure.Headers.Location!.Query);
        Assert.Equal("ABCDEFGH", query["code"].ToString());
        var callback = query["callback"].ToString();
        using var anonymous = host.GetTestClient();
        using var unauthenticatedCallback = await anonymous.GetAsync(callback);
        Assert.Equal(HttpStatusCode.BadRequest, unauthenticatedCallback.StatusCode);
        using var wrongState = await Send(HttpMethod.Get, callback + "wrong");
        Assert.Equal(HttpStatusCode.BadRequest, wrongState.StatusCode);
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var entry = store.Get(initial.Headers.Location!.ToString().Split('/')[^1])!;
        entry.ResourceContext!["account"] = "tampered";
        using var changedContext = await Send(HttpMethod.Get, callback);
        Assert.Equal(HttpStatusCode.BadRequest, changedContext.StatusCode);
        entry.ResourceContext["account"] = "work";
        using var completion = await Send(HttpMethod.Get, error is null ? callback : callback + "&error=" + Uri.EscapeDataString(error));
        Assert.Equal(error is null ? HttpStatusCode.Redirect : HttpStatusCode.OK, completion.StatusCode);
        using var replay = await Send(HttpMethod.Get, callback);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        using var result = await agent.GetAsync(initial.Headers.Location);
        Assert.Equal(expectedStatus, (int)result.StatusCode);
        if (error is null)
        {
            Assert.True(JsonNode.DeepEquals(DecodePayload(token), asserter.Last!.ResourceContext));
            var auth = DecodePayload((string)(await result.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!);
            Assert.Equal("work", (string?)auth["account"]);
            Assert.Equal("whoami", (string?)auth["scope"]);
            Assert.Equal(AgentId, (string?)auth["agent"]);
        }
        else
        {
            Assert.Null(asserter.Last);
            Assert.Equal(expectedError, (string?)(await result.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        }
    }

    [Fact]
    public async Task ResourceInteractionDefaultRequiresAuthenticatedPerson()
    {
        using var host = await BuildHostAsync();
        using var browser = host.GetTestClient();
        using var response = await browser.GetAsync("/interaction/resource?code=ABCDEFGH");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task CollapsedPersonServerRejectsForeignApproverBeforeConsent()
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var agent = SignedAgentClient(host, key, AgentId);
        using var response = await agent.PostAsJsonAsync("/token", new
        {
            resource_token = ResourceToken(key, AgentId, PsIssuer, mission: new MissionClaim("https://other-ps.test", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(asserter.Last);
    }

    [Theory]
    [InlineData("http://whoami.test/permission")]
    [InlineData("https://127.0.0.1/permission")]
    [InlineData("https://whoami.test/permission?callback=https://attacker.test")]
    public async Task ResourceInteractionRejectsUnadmittedDestination(string url)
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var agent = SignedAgentClient(host, key, AgentId);
        var original = ResourceToken(key, AgentId, PsIssuer);
        var payload = DecodePayload(original);
        payload["interaction"] = new JsonObject { ["url"] = url, ["code"] = "ABCDEFGH" };
        var token = JwtWriter.SignCompact(TokenVerifier.DecodeJsonSegment(original.Split('.')[0], "header"), payload, ResourceKey);
        using var response = await agent.PostAsJsonAsync("/token", new { resource_token = token });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(asserter.Last);
    }

    private sealed class StubAsserter : IIdentityClaimsAsserter
    {
        private readonly IdentityAssertion _assertion;
        public StubAsserter(IdentityAssertion assertion) => _assertion = assertion;
        public Task<IdentityAssertion> AssertAsync(
            IdentityAssertionRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(_assertion);
    }

    // A mission-consent seam driven by a per-context decision function, so each
    // test scripts the gate / clarify / resolve outcomes it needs.
    private sealed class StubMissionConsent : IMissionTokenConsent
    {
        private readonly Func<MissionTokenConsentContext, MissionTokenConsentDecision> _decide;
        public StubMissionConsent(Func<MissionTokenConsentContext, MissionTokenConsentDecision> decide)
            => _decide = decide;
        public Task<MissionTokenConsentDecision> ReviewAsync(
            MissionTokenConsentContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(_decide(context));
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
                jwk["alg"] = AAuthKey.Ed25519Algorithm;
                json = new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
