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
using AAuth.Server;
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
    private const string S256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private static readonly AAuthKey ResourceKey = AAuthKey.Generate();
    private static readonly AAuthKey PsKey = AAuthKey.Generate();

    private sealed class PublicDns : IAAuthDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    // Build a PS host: real verification middleware + stub resource discovery +
    // the supplied asserter (default asserts a fixed sub) and optional mission
    // consent seam (default = the conservative DefaultMissionTokenConsent).
    private static async Task<IHost> BuildHostAsync(
        IIdentityClaimsAsserter? asserter = null, IMissionTokenConsent? consent = null, bool demoResource = false,
        IJtiStore? inventory = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

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
        var personServer = builder.Services.AddAAuthPersonServer(configure: o =>
        {
            o.EgressPolicy = new AAuthEgressPolicy(dnsResolver: new PublicDns());
            o.Issuer = PsIssuer;
            o.SigningKeys = new AAuthSigningKeySet { [PsKid] = PsKey };
            o.Trust.AccessServers.Allowed = new System.Collections.Generic.HashSet<string> { AsIssuer };
            o.ResourceInteractionSessions = demoResource ? new AAuth.Server.BrowserConsentSessions("resource-tests", "demo-person", isolatedDemoAccess: _ => true) : null;
        });
        if (inventory is not null) personServer.UseTokenInventory(inventory);

        var app = builder.Build();
        app.MapAAuthPersonServer();
        await app.StartAsync();
        await app.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            S256, PsIssuer, AgentId, new byte[] { 1, 2, 3 }));
        return app;
    }

    private static async Task<HttpClient> SignedAgentClientAsync(IHost host, AAuthKey agentKey, string agentId, TimeSpan? lifetime = null,
        string? body = null)
    {
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
            Lifetime = lifetime ?? TimeSpan.FromHours(1),
        }.BuildAsync();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken);
        // body: "uncovered" signs without content-type/content-digest; "tampered"
        // swaps the body after signing, keeping the signed Content-Digest.
        if (body == "uncovered")
            return new InProcessHttpClient(new UncoveredBodySigner(signing) { InnerHandler = host.GetTestServer().CreateHandler() })
                { BaseAddress = new Uri(PsIssuer) };
        signing.InnerHandler = body == "tampered"
            ? new BodySwapHandler { InnerHandler = host.GetTestServer().CreateHandler() }
            : host.GetTestServer().CreateHandler();
        return new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
    }

    [Theory(DisplayName = "§Covered Components — a PS body not covered by content-type/content-digest, or not matching its digest, fails before the asserter")]
    [InlineData("/token", "uncovered")]
    [InlineData("/token", "tampered")]
    [InlineData("/person", "uncovered")]
    [InlineData("/person", "tampered")]
    public async Task PsBody_UncoveredOrTampered_FailsBeforeAsserter(string path, string body)
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId, body: body);

        using var response = await http.PostAsJsonAsync(path,
            path == "/token" ? await TokenRequestAsync(agentKey) : new JsonObject { ["resource"] = ResourceUrl });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var error = Assert.Single(response.Headers.GetValues("Signature-Error"));
        if (body == "uncovered")
        {
            Assert.Contains("invalid_input", error);
            Assert.Contains("content-type", error);
            Assert.Contains("content-digest", error);
        }
        else
        {
            Assert.Contains("invalid_signature", error);
        }
        Assert.Null(asserter.Last);
        await host.StopAsync();
    }

    // A person token this PS issued to the agent for the resource (§Person Token Structure).
    private static ValueTask<string> PersonTokenAsync(AAuthKey agentKey, string? missionS256 = null, string subject = "user-42")
        => new PersonTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = PsIssuer,
            Audience = ResourceUrl,
            Subject = subject,
            ConfirmationKey = agentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Key = PsKey,
            KeyId = PsKid,
            MissionS256 = missionS256,
        }.BuildAsync();

    // The resource token naming the presented person token (ps/sub/presented_jti/mission_s256).
    private static ValueTask<string> ResourceTokenAsync(
        AAuthKey agentKey, string presentedToken, string audience, string scope = "whoami", string? account = null,
        Interaction? interaction = null, string? overwrite = null)
    {
        var presented = DecodePayload(presentedToken);
        return new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = ResourceUrl,
            Audience = audience,
            PersonServer = overwrite == "ps" ? "https://other-ps.example" : PsIssuer,
            Subject = overwrite == "sub" ? "someone-else" : (string)presented["sub"]!,
            PresentedJti = overwrite == "presented_jti" ? "other-jti" : (string)presented["jti"]!,
            MissionS256 = overwrite == "mission" ? "Q7cOX4Oq4Fmc5L8FJbfyLmXDVz-lEVJbzsUNr8dlc2E" : (string?)presented["mission_s256"],
            Tenant = overwrite == "tenant" ? "other-tenant" : (string?)presented["tenant"],
            AgentJkt = (overwrite == "agent_jkt" ? AAuthKey.Generate() : agentKey).ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResKid,
            Scope = scope,
            Account = account,
            Interaction = interaction,
        }.BuildAsync();
    }

    // The §Auth Token Request body: a resource token paired with the person token it names.
    private static async Task<JsonObject> TokenRequestAsync(
        AAuthKey agentKey, string audience = PsIssuer, string scope = "whoami", string? missionS256 = null,
        string? account = null)
    {
        var personToken = await PersonTokenAsync(agentKey, missionS256);
        return new JsonObject
        {
            ["resource_token"] = await ResourceTokenAsync(agentKey, personToken, audience, scope, account),
            ["presented_token"] = personToken,
        };
    }

    // An upstream token for call chaining: `aud` MUST equal the intermediary agent
    // token's `iss` (= https://ap.example) per §Upstream Token Verification, and it
    // MUST name this PS. A PS-issued token is verified with this PS's own key; an
    // AS-issued one via the stub JWKS (ResourceKey).
    private static ValueTask<string> UpstreamTokenAsync(string issuer, string? missionS256 = null, string audience = "https://ap.example")
        => issuer == PsIssuer
            ? new PersonTokenBuilder
            {
                EgressPolicy = TestEgress.Policy,
                Issuer = PsIssuer,
                Audience = audience,
                Subject = "upstream-user",
                ConfirmationKey = AAuthKey.Generate(),
                AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                Key = PsKey,
                KeyId = PsKid,
                MissionS256 = missionS256,
            }.BuildAsync()
            : new AuthTokenBuilder
            {
                EgressPolicy = TestEgress.Policy,
                AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                Issuer = issuer,
                Dwk = AuthTokenBuilder.AccessDwk,
                Audience = audience,
                PersonServer = PsIssuer,
                AgentConfirmationKey = AAuthKey.Generate(),
                Key = ResourceKey,
                KeyId = ResKid,
                Scope = "data.read",
                Subject = "upstream-user",
                MissionS256 = missionS256,
            }.BuildAsync();

    private static JsonObject DecodePayload(string jwt)
    {
        var segments = jwt.Split('.');
        return (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;
    }

    [Fact(DisplayName = "§Person Token Endpoint — the PS issues a person token bound to the agent key for the resource")]
    public async Task PersonTokenEndpoint_IssuesPersonToken()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/person",
            new JsonObject { ["resource"] = ResourceUrl, ["mission_s256"] = S256 });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var personToken = (string)body!["person_token"]!;
        Assert.Equal(PersonTokenBuilder.TokenType,
            (string?)TokenVerifier.DecodeJsonSegment(personToken.Split('.')[0], "header")["typ"]);
        var payload = DecodePayload(personToken);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal("user-42", (string?)payload["sub"]);
        Assert.Equal(S256, (string?)payload["mission_s256"]);
        Assert.Null(payload["agent"]);
        Assert.Null(payload["scope"]);
        var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());

        await host.StopAsync();
    }

    [Theory(DisplayName = "§Person Token Structure — a person token is capped at 1 h and by the agent, upstream and mission expiry")]
    [InlineData("hour")]
    [InlineData("agent")]
    [InlineData("upstream")]
    [InlineData("mission")]
    public async Task PersonTokenEndpoint_LifetimeIsCappedByEveryBound(string bound)
    {
        var agentKey = AAuthKey.Generate();
        var now = DateTimeOffset.UtcNow;
        using var host = await BuildHostAsync();
        const string missionS256 = "Q7cOX4Oq4Fmc5L8FJbfyLmXDVz-lEVJbzsUNr8dlc2E";
        await host.Services.GetRequiredService<IMissionStore>().SaveAsync(
            new StoredMission(missionS256, PsIssuer, AgentId, new byte[] { 4, 5, 6 }) { ExpiresAt = now.AddMinutes(5) });
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId,
            bound switch { "hour" => TimeSpan.FromHours(3), "agent" => TimeSpan.FromMinutes(10), _ => TimeSpan.FromHours(1) });
        var body = new JsonObject { ["resource"] = ResourceUrl };
        if (bound == "mission") body["mission_s256"] = missionS256;
        if (bound == "upstream")
            body["upstream_token"] = await new PersonTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = PsIssuer, Audience = "https://ap.example", Subject = "upstream-user",
                ConfirmationKey = AAuthKey.Generate(), AgentTokenExpiresAt = now.AddMinutes(7), Key = PsKey, KeyId = PsKid,
            }.BuildAsync();

        using var response = await http.PostAsJsonAsync("/person", body);

        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var payload = DecodePayload((string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["person_token"]!);
        var expires = (long)payload["exp"]!;
        var ceiling = bound switch
        {
            "hour" => (long)payload["iat"]! + 3600,
            "agent" => now.AddMinutes(10).ToUnixTimeSeconds(),
            "upstream" => now.AddMinutes(7).ToUnixTimeSeconds(),
            _ => now.AddMinutes(5).ToUnixTimeSeconds(),
        };
        Assert.InRange(expires, ceiling - 5, ceiling);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§PS-asserted access — person token, then a three-party mint bound to the agent key naming the person")]
    public async Task ThreeParty_MintsAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var person = await http.PostAsJsonAsync("/person", new JsonObject { ["resource"] = ResourceUrl });
        Assert.True(person.IsSuccessStatusCode, await person.Content.ReadAsStringAsync());
        var personToken = (string)(await person.Content.ReadFromJsonAsync<JsonObject>())!["person_token"]!;

        using var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = await ResourceTokenAsync(agentKey, personToken, PsIssuer),
            ["presented_token"] = personToken,
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(PsIssuer, (string?)payload["ps"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Null(payload["agent"]);
        Assert.Null(payload["act"]);
        Assert.Equal("user-42", (string?)payload["sub"]);
        Assert.Equal(AuthTokenBuilder.PersonDwk, (string?)payload["dwk"]);
        var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());

        await host.StopAsync();
    }

    [Fact(DisplayName = "§PS Token Endpoint — a missing presented_token is a 400 invalid_request")]
    public async Task TokenRequest_MissingPresentedToken_Rejected()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var body = await TokenRequestAsync(agentKey);
        body.Remove("presented_token");

        using var response = await http.PostAsJsonAsync("/token", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)problem!["error"]);
        Assert.Equal("missing presented_token", (string?)problem["detail"]);
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Resource Token Verification — the PS rejects a resource token whose identity binding was overwritten")]
    [InlineData("ps")]
    [InlineData("sub")]
    [InlineData("presented_jti")]
    [InlineData("mission")]
    [InlineData("tenant")]
    [InlineData("agent_jkt")]
    public async Task TokenRequest_OverwrittenIdentity_Rejected(string overwrite)
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var personToken = await PersonTokenAsync(agentKey);
        var body = new JsonObject
        {
            ["resource_token"] = await ResourceTokenAsync(agentKey, personToken, PsIssuer, overwrite: overwrite),
            ["presented_token"] = personToken,
        };

        using var response = await http.PostAsJsonAsync("/token", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)problem!["error"]);
        Assert.Null(asserter.Last);
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Resource Token Verification — a resource token that does not name the presented token is rejected")]
    [InlineData("other-person-token")]
    [InlineData("other-key")]
    public async Task TokenRequest_MismatchedPresentedToken_Rejected(string variant)
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var body = await TokenRequestAsync(agentKey);
        body["presented_token"] = variant == "other-person-token"
            ? await PersonTokenAsync(agentKey)
            : await PersonTokenAsync(AAuthKey.Generate());

        using var response = await http.PostAsJsonAsync("/token", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(variant == "other-key" ? "invalid_presented_token" : "invalid_resource_token", (string?)problem!["error"]);
        await host.StopAsync();
    }

    [Fact]
    public async Task TokenRequest_MissingResourceToken_ReturnsProblemDetails()
    {
        using var host = await BuildHostAsync();
        using var client = await SignedAgentClientAsync(host, AAuthKey.Generate(), AgentId);
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

    [Fact(DisplayName = "§Sub-Agents — parent-mediated three-party mint binds the SUB-AGENT key")]
    public async Task SubAgent_ParentMediated_BindsSubAgentKey()
    {
        const string ParentId = "aauth:demo@ap.example";
        const string SubId = "aauth:demo+w1@ap.example";
        var parentKey = AAuthKey.Generate();
        var subKey = AAuthKey.Generate();

        // Sub-agent token: signed by the AP key the stub serves (ResourceKey/ResKid),
        // cnf bound to the sub-agent key, carrying parent_agent.
        var subagentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = SubId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = subKey,
            ParentAgent = ParentId,
            PersonServer = PsIssuer,
        }.BuildAsync();

        // Person + resource tokens the SUB-AGENT obtained (bound to its own key).
        var request = await TokenRequestAsync(subKey);
        request["subagent_token"] = subagentToken;

        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, parentKey, ParentId); // parent signs

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);

        // Auth token binds to the sub-agent's key and names no agent or delegation chain.
        var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
        Assert.Equal(subKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());
        Assert.Null(payload["agent"]);
        Assert.Null(payload["act"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Agent Token Request — the PS flows prompt and capabilities to the asserter")]
    public async Task TokenRequest_PromptAndCapabilities_ReachAsserter()
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        var request = await TokenRequestAsync(agentKey);
        request["prompt"] = "consent";
        request["capabilities"] = new JsonArray("interaction", "payment");
        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        Assert.NotNull(asserter.Last);
        Assert.Equal("consent", asserter.Last!.Prompt);
        Assert.NotNull(asserter.Last.Capabilities);
        Assert.Contains("interaction", asserter.Last.Capabilities!);
        Assert.Contains("payment", asserter.Last.Capabilities!);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Person Token Request — capabilities and login_hint reach the person-token decision")]
    public async Task PersonTokenRequest_CapabilitiesAndLoginHintReachAsserter()
    {
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, AAuthKey.Generate(), AgentId);

        using var response = await http.PostAsJsonAsync("/person", new JsonObject
        {
            ["resource"] = ResourceUrl, ["login_hint"] = "alice@example.com",
            ["capabilities"] = new JsonArray("interaction", "payment"),
        });

        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        Assert.True(asserter.Last!.PersonTokenRequest);
        Assert.Equal("alice@example.com", asserter.Last.LoginHint);
        Assert.Equal(["interaction", "payment"], asserter.Last.Capabilities!);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Single-Level Depth — the PS rejects a request signed by a sub-agent")]
    public async Task SubAgent_DirectRequest_Rejected()
    {
        const string ParentId = "aauth:demo@ap.example";
        const string SubId = "aauth:demo+w1@ap.example";
        var subKey = AAuthKey.Generate();

        // A sub-agent token used to SIGN the request directly (not allowed).
        var subagentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = SubId,
            KeyId = ResKid,
            Key = ResourceKey,
            ConfirmationKey = subKey,
            ParentAgent = ParentId,
            PersonServer = PsIssuer,
        }.BuildAsync();

        using var host = await BuildHostAsync();
        var signing = new AAuthSigningHandler(subKey, () => subagentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        using var response = await http.PostAsJsonAsync("/token", await TokenRequestAsync(subKey));

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
        var authTokenAsCarrier = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = PsIssuer,
            Audience = ResourceUrl,
            PersonServer = PsIssuer,
            AgentConfirmationKey = agentKey,
            Key = AAuthKey.Generate(),
            KeyId = "x",
            Subject = "pairwise",
            Scope = "whoami",
        }.BuildAsync();
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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", new JsonObject());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Token Endpoint Error Codes — an unverifiable resource_token is a 400 invalid_resource_token (not a 401)")]
    public async Task ThreeParty_RejectsInvalidResourceToken_With400()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        // A resource token carrying the published kid but signed with a different
        // key — the PS resolves the genuine JWKS key and the signature check fails.
        var personToken = await PersonTokenAsync(agentKey);
        var genuine = DecodePayload(await ResourceTokenAsync(agentKey, personToken, PsIssuer));
        var forged = await JwtWriter.SignCompactAsync(new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm, ["typ"] = ResourceTokenBuilder.TokenType, ["kid"] = ResKid,
        }, genuine, AAuthKey.Generate());

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = forged, ["presented_token"] = personToken });

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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey));

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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var post = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey));

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
        // The auth token's sub is the verified resource token's, not the consent verdict's.
        Assert.Equal("user-42", (string?)payload["sub"]);
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Auth Token Structure — an auth token never outlives its mission, immediate or deferred")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthToken_IsCappedByMissionExpiry(bool deferred)
    {
        const string missionS256 = "Q7cOX4Oq4Fmc5L8FJbfyLmXDVz-lEVJbzsUNr8dlc2E";
        var agentKey = AAuthKey.Generate();
        var missionExpiry = DateTimeOffset.UtcNow.AddMinutes(5);
        using var host = await BuildHostAsync(consent: new StubMissionConsent(context =>
            deferred && context.ClarificationHistory.Count == 0
                ? MissionTokenConsentDecision.Clarify("Why?") : MissionTokenConsentDecision.Grant()));
        await host.Services.GetRequiredService<IMissionStore>().SaveAsync(
            new StoredMission(missionS256, PsIssuer, AgentId, new byte[] { 4, 5, 6 }) { ExpiresAt = missionExpiry });
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        var response = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: missionS256));
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            var location = response.Headers.Location;
            response.Dispose();
            using var answer = await http.PostAsJsonAsync(location,
                new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = "for the trip" });
            Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
            response = await http.GetAsync(location);
        }

        using (response)
        {
            Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
            var payload = DecodePayload((string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!);
            Assert.True((long)payload["exp"]! <= missionExpiry.ToUnixTimeSeconds());
            Assert.Equal(missionS256, (string?)payload["mission_s256"]);
        }
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Consent Presentation — justification, platform and device reach the asserter as agent-asserted content, apart from resource claims")]
    [InlineData("/token")]
    [InlineData("/person")]
    public async Task AgentAssertedContent_ReachesAsserterApartFromResourceContext(string path)
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var body = path == "/token" ? await TokenRequestAsync(agentKey) : new JsonObject { ["resource"] = ResourceUrl };
        body["justification"] = "# Booking your trip";
        body["platform"] = "ios";
        body["device"] = "Pixel 8 (App)";

        using var response = await http.PostAsJsonAsync(path, body);

        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        Assert.Equal(new AgentAssertedContent { Justification = "# Booking your trip", Platform = "ios", Device = "Pixel 8 (App)" },
            asserter.Last!.AgentAsserted);
        if (path == "/token")
        {
            Assert.NotNull(asserter.Last.ResourceContext);
            Assert.False(asserter.Last.ResourceContext!.ContainsKey("justification"));
        }
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Consent Presentation — a non-string justification, platform or device is invalid_request before the asserter")]
    [InlineData("justification")]
    [InlineData("platform")]
    [InlineData("device")]
    public async Task AgentAssertedContent_NonString_Rejected(string member)
    {
        var agentKey = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var body = await TokenRequestAsync(agentKey);
        body[member] = new JsonObject();

        using var response = await http.PostAsJsonAsync("/token", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.Null(asserter.Last);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Consent Presentation — the mission Supervisor receives agent-asserted content attributed, on the gate and after a deferral")]
    public async Task AgentAssertedContent_ReachesMissionSupervisor()
    {
        var agentKey = AAuthKey.Generate();
        var seen = new List<MissionTokenConsentContext>();
        using var host = await BuildHostAsync(consent: new StubMissionConsent(context =>
        {
            seen.Add(context);
            return context.ClarificationHistory.Count == 0
                ? MissionTokenConsentDecision.Clarify("Why?") : MissionTokenConsentDecision.Grant();
        }));
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var body = await TokenRequestAsync(agentKey, missionS256: S256);
        body["justification"] = "Needed for the itinerary";

        using var first = await http.PostAsJsonAsync("/token", body);
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        using var answer = await http.PostAsJsonAsync(first.Headers.Location,
            new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = "because" });
        using var result = await http.GetAsync(first.Headers.Location);

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.True(seen.Count >= 2);
        Assert.All(seen, context => Assert.Equal("Needed for the itinerary", context.AgentAsserted?.Justification));
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Update — an accepted update reaches the Supervisor and ends the prior-consent fast path")]
    public async Task AcceptedUpdate_ReachesConsentAndResetsFastPath()
    {
        var agentKey = AAuthKey.Generate();
        var reviews = new List<MissionTokenConsentContext>();
        using var host = await BuildHostAsync(consent: new StubMissionConsent(context =>
        {
            reviews.Add(context);
            return MissionTokenConsentDecision.Grant();
        }));
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using (var first = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: S256)))
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using (var repeat = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: S256)))
            Assert.Equal(HttpStatusCode.OK, repeat.StatusCode);
        Assert.Single(reviews);

        await host.Services.GetRequiredService<IMissionLog>().AppendAsync(
            new MissionLogEntry(S256, MissionLogEntryKind.Update, DateTimeOffset.UtcNow) { Detail = "{\"description\":\"Only economy\"}" });
        using (var afterUpdate = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: S256)))
            Assert.Equal(HttpStatusCode.OK, afterUpdate.StatusCode);

        Assert.Equal(2, reviews.Count);
        Assert.Empty(reviews[0].AcceptedUpdates);
        Assert.Equal("{\"description\":\"Only economy\"}", Assert.Single(reviews[1].AcceptedUpdates).Detail);

        // The consent given after the update restores the fast path.
        using (var again = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: S256)))
            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(2, reviews.Count);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Token Revocation — the five-minute resource token does not cap the auth token or its revocable grant")]
    public async Task ResourceTokenLifetime_DoesNotCapAuthTokenOrGrant()
    {
        var clock = new InventoryClock();
        var inventory = new InMemoryJtiStore(clock);
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(inventory: inventory);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = await TokenRequestAsync(agentKey);
        var resourceExp = (long)DecodePayload((string)request["resource_token"]!)["exp"]!;
        var person = DecodePayload((string)request["presented_token"]!);

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var auth = DecodePayload((string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!);
        Assert.True((long)auth["exp"]! - resourceExp > 30 * 60, "The auth token must not be capped at the resource token's expiry.");

        // Past the resource token's expiry, the grant is still tracked: revoking its source reaches it.
        clock.Now = DateTimeOffset.FromUnixTimeSeconds(resourceExp).AddMinutes(1);
        inventory.Cleanup();
        await inventory.RevokeAsync(new TokenKey(PsIssuer, (string)person["jti"]!), DateTimeOffset.FromUnixTimeSeconds((long)person["exp"]!));
        Assert.True(await inventory.IsRevokedAsync(new TokenKey(PsIssuer, (string)auth["jti"]!)));
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Token Revocation — a withdrawn resource token is revoked_resource_token, and ends a pending request with revoked")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RevokedResourceToken_RejectedAndEndsPending(bool pending)
    {
        var inventory = new InMemoryJtiStore();
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync(inventory: inventory,
            consent: pending ? new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?")) : null);
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = pending ? await TokenRequestAsync(agentKey, missionS256: S256) : await TokenRequestAsync(agentKey);
        var resource = DecodePayload((string)request["resource_token"]!);
        var resourceKey = new TokenKey((string)resource["iss"]!, (string)resource["jti"]!);
        var resourceExp = DateTimeOffset.FromUnixTimeSeconds((long)resource["exp"]!);

        if (!pending)
        {
            // The resource withdrew the token before the agent sent it: recorded unseen, refused by name.
            await inventory.RevokeAsync(resourceKey, resourceExp);
            using var rejected = await http.PostAsJsonAsync("/token", request);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Equal("revoked_resource_token", (string?)(await rejected.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        }
        else
        {
            using var first = await http.PostAsJsonAsync("/token", request);
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
            await inventory.RevokeAsync(resourceKey, resourceExp);
            using var poll = await http.GetAsync(first.Headers.Location);
            Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
            Assert.Equal("revoked", (string?)(await poll.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        }
        await host.StopAsync();
    }

    private sealed class InventoryClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
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
        using var owner = await SignedAgentClientAsync(host, agentKey, AgentId);
        using var first = await owner.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: S256));
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        using var attacker = await SignedAgentClientAsync(host, AAuthKey.Generate(),
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
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", await TokenRequestAsync(key, missionS256: S256));
        using var response = await client.PostAsJsonAsync(initial.Headers.Location,
            new JsonObject { ["action"] = action, ["clarification_response"] = "approve" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var poll = await client.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("malformed")]
    [InlineData("subject")]
    [InlineData("key")]
    [InlineData("audience")]
    [InlineData("missing-presented")]
    public async Task Clarification_ReplacementIsVerifiedAndChangesConsentScope(string variant)
    {
        var key = AAuthKey.Generate();
        MissionTokenConsentContext? reviewed = null;
        using var host = await BuildHostAsync(consent: new StubMissionConsent(context =>
        {
            reviewed = context;
            return context.Scope == "read" ? MissionTokenConsentDecision.Grant() : MissionTokenConsentDecision.Clarify("Narrow scope?");
        }));
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", await TokenRequestAsync(key, scope: "read write", missionS256: S256));
        var replacementKey = variant == "key" ? AAuthKey.Generate() : key;
        var replacementPerson = await PersonTokenAsync(replacementKey, S256, variant == "subject" ? "someone-else" : "user-42");
        var replacement = variant == "malformed" ? "not-a-jwt" : await ResourceTokenAsync(
            replacementKey, replacementPerson, variant == "audience" ? AsIssuer : PsIssuer, "read");
        var update = new JsonObject { ["action"] = "updated_request", ["resource_token"] = replacement };
        if (variant != "missing-presented") update["presented_token"] = replacementPerson;
        using var response = await client.PostAsJsonAsync(initial.Headers.Location, update);
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
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        using var initial = await client.PostAsJsonAsync("/token", await TokenRequestAsync(key));
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var id = initial.Headers.Location!.ToString().Split('/')[^1];
        if (allow) { store.MarkAllowed(id, "user"); store.MarkDenied(id, "reversal"); }
        else { store.MarkDenied(id, "denied"); store.MarkAllowed(id, "reversal"); }
        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => client.GetAsync(initial.Headers.Location)));
        Assert.Single(responses, response => response.StatusCode == (allow ? HttpStatusCode.OK : HttpStatusCode.Forbidden));
        Assert.Equal(11, responses.Count(response => response.StatusCode == HttpStatusCode.Gone));
        foreach (var response in responses) response.Dispose();
    }

    [Theory(DisplayName = "§Mission Status Errors — a terminated or expired mission is rejected (403 mission_terminated) at /token and /person")]
    [InlineData("/token", false)]
    [InlineData("/token", true)]
    [InlineData("/person", false)]
    [InlineData("/person", true)]
    public async Task Mission_Terminated_Rejected(string path, bool expired)
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var missions = host.Services.GetRequiredService<IMissionStore>();
        await missions.SaveAsync(new StoredMission(s256, PsIssuer, AgentId, new byte[] { 1, 2, 3 })
            { ExpiresAt = expired ? DateTimeOffset.UtcNow.AddSeconds(-1) : null });
        if (!expired) await missions.SetStateAsync(s256, MissionState.Terminated);

        using var response = await http.PostAsJsonAsync(path, path == "/token"
            ? await TokenRequestAsync(agentKey, missionS256: s256)
            : new JsonObject { ["resource"] = ResourceUrl, ["mission_s256"] = s256 });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("mission_terminated", (string?)body!["error"]);
        // mission_status is always "terminated"; expiry is the termination_reason.
        Assert.Equal("terminated", (string?)body["mission_status"]);
        Assert.Equal(expired ? "expired" : null, (string?)body["termination_reason"]);
        await host.StopAsync();
    }

    [Fact]
    public async Task AccountMission_IdentityDenialCannotCreatePriorConsent()
    {
        var reviews = 0;
        var key = AAuthKey.Generate();
        using var host = await BuildHostAsync(new StubAsserter(IdentityAssertion.Deny("denied identity")),
            new StubMissionConsent(_ => { reviews++; return MissionTokenConsentDecision.Grant(); }));
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        const string hash = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/token",
                await TokenRequestAsync(key, missionS256: hash, account: "personal"));
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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        using var response = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: s256));

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var payload = DecodePayload((string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(s256, (string?)payload["mission_s256"]);
        Assert.Null(payload["mission"]);

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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var first = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: s256));

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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var first = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: s256));
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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var first = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: s256));
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
        using var owner = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var first = await owner.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, missionS256: s256));
        var pendingUrl = first.Headers.Location!.ToString();

        // A different, validly-signed agent must not touch the owner's pending entry.
        using var attacker = await SignedAgentClientAsync(host, AAuthKey.Generate(), "aauth:attacker@ap.example");
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
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);

        using var response = await http.PostAsJsonAsync("/token", await TokenRequestAsync(agentKey, "https://untrusted-as.test"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_access_server", (string?)body!["error"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Upstream Token Verification — an upstream auth token from an untrusted AS is rejected")]
    public async Task CallChaining_UntrustedAsUpstream_Rejected()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = await TokenRequestAsync(agentKey);
        request["upstream_token"] = await UpstreamTokenAsync("https://untrusted-as.test");

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_upstream_token", (string?)body!["error"]);
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Upstream Token Verification — an upstream token not audienced to the intermediary's own AP is rejected at the PS")]
    [InlineData(PsIssuer, "/token")]
    [InlineData(PsIssuer, "/person")]
    [InlineData(AsIssuer, "/token")]
    public async Task CallChaining_UpstreamAudienceMustBeIntermediaryIssuer(string upstreamIssuer, string path)
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = path == "/token" ? await TokenRequestAsync(agentKey) : new JsonObject { ["resource"] = ResourceUrl };
        // The intermediary's agent token is from https://ap.example; this upstream names another AP.
        request["upstream_token"] = await UpstreamTokenAsync(upstreamIssuer, audience: "https://other-ap.example");

        using var response = await http.PostAsJsonAsync(path, request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_upstream_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Call Chaining — a PS-issued upstream person token without a mission is allowed")]
    public async Task CallChaining_ThreePartyUpstream_NoMission_Allowed()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = await TokenRequestAsync(agentKey);
        request["upstream_token"] = await UpstreamTokenAsync(PsIssuer);

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string)body!["auth_token"]!);
        // The downstream sub is the resource token's; the upstream sub is never copied forward.
        Assert.Equal("user-42", (string?)payload["sub"]);
        Assert.Null(payload["act"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Call Chaining — an AS-issued upstream auth token with a mission is allowed")]
    public async Task CallChaining_FourPartyUpstream_WithMission_Allowed()
    {
        var agentKey = AAuthKey.Generate();
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = await TokenRequestAsync(agentKey, missionS256: s256);
        request["upstream_token"] = await UpstreamTokenAsync(AsIssuer, s256);

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Call Chaining — a downstream request must retain the upstream mission")]
    public async Task CallChaining_UpstreamMissionMustBeRetained()
    {
        var agentKey = AAuthKey.Generate();
        using var host = await BuildHostAsync();
        using var http = await SignedAgentClientAsync(host, agentKey, AgentId);
        var request = await TokenRequestAsync(agentKey);
        request["upstream_token"] = await UpstreamTokenAsync(AsIssuer, S256);

        using var response = await http.PostAsJsonAsync("/token", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
        await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Clarification_UpstreamMissionCannotBeStrippedOrChanged(bool changed)
    {
        var key = AAuthKey.Generate();
        using var host = await BuildHostAsync(consent: new StubMissionConsent(_ => MissionTokenConsentDecision.Clarify("Why?")));
        var missions = host.Services.GetRequiredService<IMissionStore>();
        await missions.SaveAsync(new StoredMission(S256, PsIssuer, "aauth:upstream-caller@ap.example", new byte[] { 1 }));
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        var request = await TokenRequestAsync(key, missionS256: S256);
        var original = (string)request["resource_token"]!;
        request["upstream_token"] = await UpstreamTokenAsync(AsIssuer, S256);
        using var initial = await client.PostAsJsonAsync("/token", request);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var store = host.Services.GetRequiredService<IPersonPendingStore>();
        var id = initial.Headers.Location!.ToString().Split('/')[^1];
        var entry = store.Get(id)!;
        var replacementPerson = await PersonTokenAsync(key, changed ? "eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" : null);
        using var replacement = await client.PostAsJsonAsync(initial.Headers.Location, new
        {
            action = "updated_request",
            resource_token = await ResourceTokenAsync(key, replacementPerson, PsIssuer),
            presented_token = replacementPerson,
        });
        Assert.Equal(HttpStatusCode.BadRequest, replacement.StatusCode);
        Assert.Equal(original, entry.ResourceToken);
        Assert.Equal(S256, entry.MissionS256);
        Assert.True(entry.MissionGate);
        Assert.Equal(0, entry.ClarificationRounds);
        await missions.SetStateAsync(S256, MissionState.Terminated);
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
        const string mission = "eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        if (variant != "unknown")
            await host.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
                mission, variant == "stored-approver" ? "https://other-ps.test" : PsIssuer,
                variant == "foreign-owner" ? "aauth:other@ap.example" : AgentId, new byte[] { 1 }));
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        var personToken = await PersonTokenAsync(key, mission);
        var resourceToken = await ResourceTokenAsync(key, personToken, PsIssuer,
            interaction: interaction ? new Interaction(ResourceUrl + "/permission", "ABCDEFGH") : null);
        using var response = await client.PostAsJsonAsync("/token", new
        {
            resource_token = resourceToken,
            presented_token = personToken,
        });
        // §Mission Status Errors: an unknown or foreign mission is mission_not_found.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("mission_not_found", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
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
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter, new StubMissionConsent(context =>
            deferred && context.ClarificationHistory.Count == 0
                ? MissionTokenConsentDecision.Clarify("Why?") : MissionTokenConsentDecision.Grant()));
        var childToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = "https://ap.example", Subject = child,
            KeyId = ResKid, Key = ResourceKey, ConfirmationKey = childKey, ParentAgent = AgentId, PersonServer = PsIssuer,
        }.BuildAsync();
        using var client = await SignedAgentClientAsync(host, parentKey, AgentId);
        var request = await TokenRequestAsync(childKey, missionS256: S256);
        request["subagent_token"] = childToken;
        using var initial = await client.PostAsJsonAsync("/token", request);
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
            Assert.Null(payload["agent"]);
            Assert.Equal(childKey.ComputeJwkThumbprint(), AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!).ComputeJwkThumbprint());
        }
    }

    [Fact]
    public async Task ResourceInteractionPrecedesIdentityAndConsent()
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var client = await SignedAgentClientAsync(host, key, AgentId);
        var personToken = await PersonTokenAsync(key);
        var original = await ResourceTokenAsync(key, personToken, PsIssuer);
        var payload = DecodePayload(original);
        payload["interaction"] = new JsonObject { ["url"] = ResourceUrl + "/permission", ["code"] = "ABCDEFGH" };
        var header = TokenVerifier.DecodeJsonSegment(original.Split('.')[0], "header");
        var token = await JwtWriter.SignCompactAsync(header, payload, ResourceKey);
        using var response = await client.PostAsJsonAsync("/token", new { resource_token = token, presented_token = personToken });
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
        using var agent = await SignedAgentClientAsync(host, key, AgentId);
        var personToken = await PersonTokenAsync(key);
        var token = await ResourceTokenAsync(key, personToken, PsIssuer, account: "work",
            interaction: new Interaction(ResourceUrl + "/permission", "ABCDEFGH"));
        using var initial = await agent.PostAsJsonAsync("/token", new { resource_token = token, presented_token = personToken });
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
            Assert.Null(auth["agent"]);
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

    [Theory]
    [InlineData("http://whoami.test/permission")]
    [InlineData("https://127.0.0.1/permission")]
    [InlineData("https://whoami.test/permission?callback=https://attacker.test")]
    public async Task ResourceInteractionRejectsUnadmittedDestination(string url)
    {
        var key = AAuthKey.Generate();
        var asserter = new CapturingAsserter();
        using var host = await BuildHostAsync(asserter);
        using var agent = await SignedAgentClientAsync(host, key, AgentId);
        var personToken = await PersonTokenAsync(key);
        var original = await ResourceTokenAsync(key, personToken, PsIssuer);
        var payload = DecodePayload(original);
        payload["interaction"] = new JsonObject { ["url"] = url, ["code"] = "ABCDEFGH" };
        var token = await JwtWriter.SignCompactAsync(TokenVerifier.DecodeJsonSegment(original.Split('.')[0], "header"), payload, ResourceKey);
        using var response = await agent.PostAsJsonAsync("/token", new { resource_token = token, presented_token = personToken });
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
