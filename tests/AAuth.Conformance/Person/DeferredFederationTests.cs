using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Governance;
using AAuth.Server.CallChaining;
using AAuth.Tokens;
using AAuth.Testing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AAuth.Conformance.Person;

public class DeferredFederationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FederatedResourceCallbackControlsAuthorization(bool denied)
    {
        var asserter = new ConsentAsserter(IdentityAssertion.Assert("person"));
        await using var fixture = await Fixture.CreateAsync("immediate", asserter);
        var token = new ResourceTokenBuilder
        {
            Issuer = "https://resource.test", Audience = "https://as.test", Agent = "aauth:demo@ap.test",
            AgentJkt = fixture.AgentKey.ComputeJwkThumbprint(), Key = fixture.ResourceKey, KeyId = "key",
            Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource, Account = "work",
            Interaction = new Interaction("https://8.8.8.8/permission", "ABCDEFGH"),
        }.Build();
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = token });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
        var interaction = Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues(AAuthRequirementHeader.Name).Single()))!;
        using var browser = fixture.PersonApp.GetTestClient();
        browser.BaseAddress = new Uri(Fixture.PsIssuer);
        var cookies = new Dictionary<string, string>();
        async Task<HttpResponseMessage> Send(HttpMethod method, string url, Dictionary<string, string>? fields = null)
        {
            using var request = new HttpRequestMessage(method, url);
            if (cookies.Count > 0) request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies.Values));
            if (fields is not null) request.Content = new FormUrlEncodedContent(fields);
            var response = await browser.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
                foreach (var value in values) { var cookie = value.Split(';')[0]; cookies[cookie.Split('=')[0]] = cookie; }
            return response;
        }
        using var login = await Send(HttpMethod.Get, interaction.BuildUserUrl());
        using var signIn = await Send(HttpMethod.Post, interaction.BuildUserUrl(), new()
        {
            ["sign_in"] = "demo", ["csrf"] = TestConsentBrowser.Field(await login.Content.ReadAsStringAsync(), "csrf"),
        });
        using var entered = await Send(HttpMethod.Get, signIn.Headers.Location!.ToString());
        using var interstitial = await Send(HttpMethod.Get, entered.Headers.Location!.ToString());
        var html = await interstitial.Content.ReadAsStringAsync();
        using var forged = await Send(HttpMethod.Post, "/interaction/resource/continue", new()
        {
            ["session"] = TestConsentBrowser.Field(html, "session"), ["csrf"] = "wrong",
        });
        Assert.Equal(HttpStatusCode.Forbidden, forged.StatusCode);
        using var departure = await Send(HttpMethod.Post, "/interaction/resource/continue", new()
        {
            ["session"] = TestConsentBrowser.Field(html, "session"), ["csrf"] = TestConsentBrowser.Field(html, "csrf"),
        });
        Assert.Equal(HttpStatusCode.Redirect, departure.StatusCode);
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
        var callback = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(departure.Headers.Location!.Query)["callback"].ToString();
        using var completed = await Send(HttpMethod.Get, denied ? callback + "&error=access_denied" : callback);
        Assert.Equal(denied ? HttpStatusCode.OK : HttpStatusCode.Redirect, completed.StatusCode);
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(denied ? HttpStatusCode.Forbidden : HttpStatusCode.OK, result.StatusCode);
        var body = (await result.Content.ReadFromJsonAsync<JsonObject>())!;
        if (denied)
        {
            Assert.Equal("denied", (string?)body["error"]);
            Assert.Equal(0, asserter.Calls);
            Assert.Null(fixture.Policy.Last);
        }
        else
        {
            var payload = TokenVerifier.DecodeJsonSegment(((string)body["auth_token"]!).Split('.')[1], "payload");
            Assert.Equal("https://as.test", (string?)payload["iss"]);
            Assert.Equal("work", (string?)payload["account"]);
            Assert.Equal("read", (string?)payload["scope"]);
            Assert.NotNull(fixture.Policy.Last);
        }
    }

    [Fact]
    public async Task FederatedResourceInteractionPrecedesIdentityAndAccessPolicy()
    {
        var asserter = new ConsentAsserter(IdentityAssertion.Assert("person"));
        await using var fixture = await Fixture.CreateAsync("immediate", asserter);
        var token = new ResourceTokenBuilder
        {
            Issuer = "https://resource.test", Audience = "https://as.test", Agent = "aauth:demo@ap.test",
            AgentJkt = fixture.AgentKey.ComputeJwkThumbprint(), Key = fixture.ResourceKey, KeyId = "key",
            Interaction = new Interaction("https://8.8.8.8/permission", "ABCDEFGH"),
        }.Build();
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = token });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Contains("https://ps.test/interaction/resource", initial.Headers.GetValues(AAuthRequirementHeader.Name).Single());
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
        using var poll = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
        using var cancel = await fixture.Agent.DeleteAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.NoContent, cancel.StatusCode);
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
    }

    [Fact]
    public async Task UnstructuredFederationErrorsNeverReachPersonLogs()
    {
        await using var fixture = await Fixture.CreateAsync("unstructured-error");
        using var response = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") });
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var logs = string.Join("\n", fixture.Logs.Messages);
        Assert.Contains("federation", logs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("TOKEN-SECRET-SENTINEL", logs);
        Assert.DoesNotContain("person-sentinel@example.test", logs);
        Assert.DoesNotContain("forged-log-line", logs);
    }

    private sealed class Logs : ILoggerProvider, ILogger
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Enqueue(formatter(state, exception) + exception);
        public void Dispose() { }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissionApproverMustBeAuthenticatedPs(bool replacement)
    {
        await using var fixture = await Fixture.CreateAsync(replacement ? "update" : "immediate");
        var foreign = new MissionClaim("https://other-ps.test", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken(replacement ? "read write" : "read", mission: replacement ? null : foreign),
        });
        if (replacement)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            using var response = await fixture.Ps.PostAsJsonAsync(initial.Headers.Location, new
            {
                action = "updated_request", resource_token = fixture.ResourceToken("read", mission: foreign),
            });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("read write", fixture.AsEntry.Scope);
            Assert.Null(fixture.AsEntry.ResourceContext!["mission"]);
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, initial.StatusCode);
            Assert.Null(fixture.Policy.Last);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DirectAsChainingUsesAccessMetadataAndAgentCarrier(bool rawEndpoint)
    {
        await using var fixture = await Fixture.CreateAsync("immediate");
        var upstream = fixture.UpstreamToken();
        using var client = fixture.DirectClient();
        string auth;
        if (rawEndpoint)
        {
            using var response = await client.PostAsJsonAsync("/token", new
            { resource_token = fixture.ResourceToken("read", account: "work"), upstream_token = upstream });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            auth = (await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!.GetValue<string>();
        }
        else
        {
            var exchange = new TokenExchangeClient(client, fixture.AccessApp.Services.GetRequiredService<MetadataClient>());
            auth = await new CallChainingHandler(exchange, new CallChainingOptions
            { AgentKey = fixture.AgentKey, SignatureKeyProvider = new JwtSignatureKeyProvider(() => fixture.AgentToken) })
                .ExchangeForDownstreamAsync(upstream, fixture.ResourceToken("read", account: "work"), account: "work");
        }
        var payload = Payload(auth);
        Assert.Equal("jwt", fixture.DirectRequest!.Scheme);
        Assert.Equal(upstream, (string?)fixture.DirectRequest.Body!["upstream_token"]);
        Assert.False(fixture.DirectRequest.Body.ContainsKey("agent_token"));
        Assert.Contains("https://as.test/.well-known/aauth-access.json", fixture.DiscoveryTransport.Paths);
        Assert.DoesNotContain("https://as.test/.well-known/aauth-person.json", fixture.DiscoveryTransport.Paths);
        Assert.Equal("https://as.test", (string?)payload["iss"]);
        Assert.Equal("work", (string?)payload["account"]);
        Assert.Equal("aauth:original@origin.test", (string?)payload["act"]?["agent"]);
        Assert.NotEqual("upstream-person", (string?)payload["sub"]);
        Assert.Null(fixture.Policy.Last!.PersonServerIssuer);
        Assert.Equal("upstream-person", fixture.Policy.Last.UpstreamAuthorization!.Subject);
        Assert.Equal(fixture.AgentKey.ComputeJwkThumbprint(), KeyFactory.FromPublicJwk(payload["cnf"]!["jwk"]!.AsObject()).ComputeJwkThumbprint());
    }

    [Theory]
    [InlineData("missing-upstream")]
    [InlineData("upstream-issuer")]
    [InlineData("upstream-audience")]
    [InlineData("mission")]
    [InlineData("agent")]
    [InlineData("key")]
    [InlineData("body-agent")]
    public async Task DirectAsChainingRejectsUnboundAuthorization(string variant)
    {
        await using var fixture = await Fixture.CreateAsync("immediate");
        using var client = fixture.DirectClient();
        using var result = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["resource_token"] = fixture.ResourceToken("read", variant),
            ["upstream_token"] = variant == "missing-upstream" ? null : fixture.UpstreamToken(variant),
            ["agent_token"] = variant == "body-agent" ? new AgentTokenBuilder
            {
                Issuer = "https://ap.test", Subject = "aauth:spoof@ap.test", Key = fixture.ApKey, KeyId = "key", ConfirmationKey = fixture.AgentKey,
            }.Build() : null,
        });
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null(fixture.Policy.Last);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public async Task DirectAsPendingBindsAgentIssuerSubjectAndKey(string method)
    {
        await using var fixture = await Fixture.CreateAsync("interaction");
        using var owner = fixture.DirectClient();
        using var initial = await owner.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read"), upstream_token = fixture.UpstreamToken() });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        foreach (var changed in new[] { "subject", "key", "issuer", "ps" })
        {
            var key = changed == "key" ? AAuthKey.Generate() : fixture.AgentKey;
            var token = new AgentTokenBuilder
            {
                Issuer = changed == "issuer" ? "https://other-resource.test" : "https://ap.test",
                Subject = changed == "subject" ? "aauth:other@ap.test" : "aauth:demo@ap.test",
                Key = changed == "issuer" ? fixture.ResourceKey : fixture.ApKey, KeyId = "key", ConfirmationKey = key,
            }.Build();
            using var foreign = changed == "ps" ? fixture.PsClient(Fixture.PsIssuer, "second")
                : new AAuthClientBuilder(key).UseJwt(token).WithEgressPolicy(TestEgress.Policy)
                    .WithInnerHandler(fixture.AccessApp.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
            using var request = new HttpRequestMessage(new HttpMethod(method), "https://as.test" + initial.Headers.Location);
            if (method == "POST") request.Content = JsonContent.Create(new { sub = "spoofed" });
            using var rejected = await foreign.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        }
        fixture.Store.MarkAllowed(fixture.AsEntry.Id);
        using var grant = await owner.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
        using var replay = await owner.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DirectAsDeferredSourceRevocationAndClarification(bool revoke)
    {
        await using var fixture = await Fixture.CreateAsync("answer");
        using var owner = fixture.DirectClient();
        var upstream = fixture.UpstreamToken();
        using var initial = await owner.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken(), upstream_token = upstream });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        if (revoke)
        {
            using var issuer = new AAuthClientBuilder(fixture.AsKey).UseJwksUri("https://as.test", AuthTokenBuilder.AccessDwk, "key")
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(fixture.AccessApp.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
            Assert.Equal(HttpStatusCode.OK, await new RevocationClient(issuer).RevokeAsync(new Uri("https://as.test/revoke"),
                new TokenKey("https://as.test", (string)Payload(upstream)["jti"]!)));
        }
        using var answer = await owner.PostAsJsonAsync(initial.Headers.Location, new { action = "clarification_response", clarification_response = "resource policy approved" });
        Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
        using var result = await owner.GetAsync(initial.Headers.Location);
        Assert.Equal(revoke ? HttpStatusCode.BadRequest : HttpStatusCode.OK, result.StatusCode);
    }

    [Fact]
    public async Task DirectAsNeverAcceptsIntermediaryIdentityClaims()
    {
        await using var fixture = await Fixture.CreateAsync("claims");
        using var owner = fixture.DirectClient();
        using var response = await owner.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read"), upstream_token = fixture.UpstreamToken() });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(fixture.Store.Last);
    }

    [Theory]
    [InlineData(true, "immediate")]
    [InlineData(true, "claims")]
    [InlineData(false, "immediate")]
    [InlineData(false, "claims")]
    [InlineData(false, "immediate", "")]
    [InlineData(false, "claims", "")]
    public async Task FederatedMissionGatePrecedesIdentityAndAccessServer(bool terminated, string outcome, string scope = "read")
    {
        var asserter = new ConsentAsserter(IdentityAssertion.Assert("user"));
        var consent = new MissionConsent(MissionTokenConsentDecision.Deny("unapproved account/scope"));
        await using var fixture = await Fixture.CreateAsync(outcome, asserter, consent);
        var mission = new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        await fixture.PersonApp.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            mission.S256, mission.Approver, "aauth:demo@ap.test", ReadOnlyMemory<byte>.Empty)
        { State = terminated ? MissionState.Terminated : MissionState.Active });
        using var result = await fixture.Agent.PostAsJsonAsync("/token", new
        { resource_token = fixture.ResourceToken(scope, mission: mission, account: "work") });
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        Assert.Equal(terminated ? "mission_terminated" : "denied", (await result.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
        if (!terminated)
        {
            Assert.Equal("work", consent.Last!.Account);
            Assert.Equal(scope, consent.Last.Scope);
            Assert.Equal(fixture.AgentKey.ComputeJwkThumbprint(), consent.Last.AgentKeyThumbprint);
        }
    }

    private sealed class MissionConsent(MissionTokenConsentDecision decision) : IMissionTokenConsent
    {
        public MissionTokenConsentDecision Decision { get; set; } = decision;
        public MissionTokenConsentContext? Last { get; private set; }
        public Task<MissionTokenConsentDecision> ReviewAsync(MissionTokenConsentContext context, CancellationToken cancellationToken = default)
        {
            Last = context;
            return Task.FromResult(Decision);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task FederatedMissionResumesSharedGate(bool clarify, bool terminate)
    {
        var consent = new MissionConsent(clarify ? MissionTokenConsentDecision.Clarify("Why?") : MissionTokenConsentDecision.Interact());
        var asserter = new ConsentAsserter(IdentityAssertion.Assert("user"));
        await using var fixture = await Fixture.CreateAsync("claims", asserter, consent);
        var mission = new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var missions = fixture.PersonApp.Services.GetRequiredService<IMissionStore>();
        await missions.SaveAsync(new StoredMission(mission.S256, mission.Approver, "aauth:demo@ap.test", ReadOnlyMemory<byte>.Empty));
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read", mission: mission, account: "work") });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Equal(0, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
        if (clarify)
        {
            using var answer = await fixture.Agent.PostAsJsonAsync(initial.Headers.Location, new { action = "clarification_response", clarification_response = "approved intent" });
            Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
        }
        consent.Decision = MissionTokenConsentDecision.Grant();
        if (terminate) await missions.SetStateAsync(mission.S256, MissionState.Terminated);
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(terminate ? HttpStatusCode.Forbidden : HttpStatusCode.OK, result.StatusCode);
        if (terminate)
        {
            Assert.Equal("mission_terminated", (await result.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
            Assert.Null(fixture.Policy.Last);
            Assert.Equal(0, asserter.Calls);
        }
        else
        {
            var auth = Payload((await result.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!.GetValue<string>());
            Assert.Equal("work", (string?)auth["account"]);
            Assert.True(JsonNode.DeepEquals(mission.ToJsonObject(), auth["mission"]));
        }
    }

    [Fact]
    public async Task FederatedMissionBrowserApprovalCoversSameContextClaimsRequest()
    {
        await using var fixture = await Fixture.CreateAsync("claims", missionConsent: new MissionConsent(MissionTokenConsentDecision.Interact()));
        var mission = new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        await fixture.PersonApp.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            mission.S256, mission.Approver, "aauth:demo@ap.test", ReadOnlyMemory<byte>.Empty));
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read", mission: mission, account: "work") });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues("AAuth-Requirement").Single()))!;
        using var browser = fixture.PersonApp.GetTestClient();
        browser.BaseAddress = new Uri(Fixture.PsIssuer);
        using var approval = await TestConsentBrowser.DecideAsync(browser, "/interaction?code=" + interaction.Code, "/interaction/approve");
        Assert.Equal(HttpStatusCode.NoContent, approval.StatusCode);
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
    }

    [Fact]
    public async Task MissionTerminationWhileAsWaitsPreventsDelivery()
    {
        await using var fixture = await Fixture.CreateAsync("interaction", missionConsent: new MissionConsent(MissionTokenConsentDecision.Grant()));
        var mission = new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var store = fixture.PersonApp.Services.GetRequiredService<IMissionStore>();
        await store.SaveAsync(new StoredMission(mission.S256, mission.Approver, "aauth:demo@ap.test", ReadOnlyMemory<byte>.Empty));
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read", mission: mission) });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        await store.SetStateAsync(mission.S256, MissionState.Terminated);
        fixture.Store.MarkAllowed(fixture.AsEntry.Id);
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        Assert.Equal("mission_terminated", (string?)(await result.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Fact]
    public async Task AsConsentClarificationAndReconsentRotateOnlyBrowserCode()
    {
        await using var fixture = await Fixture.CreateAsync("reconsent");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read"), agent_token = fixture.AgentToken });
        var originalCode = fixture.AsEntry.Browser.Code;
        using var browser = fixture.AccessApp.GetTestClient();
        browser.BaseAddress = new Uri("https://as.test");
        using var firstDecision = await TestConsentBrowser.DecideAsync(browser, "/interaction/login?code=" + originalCode, "/interaction/approve");
        Assert.Equal(HttpStatusCode.NoContent, firstDecision.StatusCode);
        using var clarification = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal("requirement=clarification", clarification.Headers.GetValues("AAuth-Requirement").Single());
        using var answer = await fixture.Ps.PostAsJsonAsync(initial.Headers.Location,
            new { action = "clarification_response", clarification_response = "reviewed" });
        Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
        using var reconsent = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, reconsent.StatusCode);
        Assert.Equal(initial.Headers.Location, reconsent.Headers.Location);
        Assert.NotEqual(originalCode, fixture.AsEntry.Browser.Code);
        Assert.Null(fixture.Store.GetByCode(originalCode));
        using var secondDecision = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/login?code=" + fixture.AsEntry.Browser.Code, "/interaction/approve");
        Assert.Equal(HttpStatusCode.NoContent, secondDecision.StatusCode);
        using var grant = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
        using var replay = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public async Task EvictedPendingIdentifiersRemainGone(string method)
    {
        await using var fixture = await Fixture.CreateAsync("interaction");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read"), agent_token = fixture.AgentToken });
        fixture.Store.Clear();
        using var request = new HttpRequestMessage(new HttpMethod(method), initial.Headers.Location);
        using var response = await fixture.Ps.SendAsync(request);
        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        using var unknown = await fixture.Ps.GetAsync("/pending/" + Guid.NewGuid().ToString("N"));
        Assert.Equal(HttpStatusCode.Gone, unknown.StatusCode);
    }

    [Fact]
    public async Task PsReconsentForClaimsUsesNewCodeOnSamePendingUrl()
    {
        var asserter = new ConsentAsserter(IdentityAssertion.NeedsConsent());
        await using var fixture = await Fixture.CreateAsync("claims", asserter);
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") });
        var original = Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues("AAuth-Requirement").Single()))!;
        using var browser = fixture.PersonApp.GetTestClient();
        browser.BaseAddress = new Uri(Fixture.PsIssuer);
        using var firstDecision = await TestConsentBrowser.DecideAsync(browser, "/interaction?code=" + original.Code, "/interaction/approve");
        Assert.Equal(HttpStatusCode.NoContent, firstDecision.StatusCode);
        HttpResponseMessage? second = null;
        for (var attempt = 0; attempt < 100; attempt++)
        {
            second = await fixture.Agent.GetAsync(initial.Headers.Location);
            if (second.Headers.TryGetValues("AAuth-Requirement", out var headers)
                && Interaction.FromRequirement(AAuthRequirementHeader.Parse(headers.Single())) is { } next && next.Code != original.Code) break;
            second.Dispose();
            second = null;
            await Task.Delay(10);
        }
        using var renewed = second ?? throw new TimeoutException("Second PS consent was not surfaced.");
        Assert.Equal(initial.Headers.Location, renewed.Headers.Location);
        var interaction = Interaction.FromRequirement(AAuthRequirementHeader.Parse(renewed.Headers.GetValues("AAuth-Requirement").Single()))!;
        var store = fixture.PersonApp.Services.GetRequiredService<IPersonPendingStore>();
        Assert.Null(store.GetByCode(original.Code!));
        Assert.NotNull(store.GetByCode(interaction.Code!.ToLowerInvariant()));
        using var finalDecision = await TestConsentBrowser.DecideAsync(browser, "/interaction?code=" + interaction.Code, "/interaction/approve");
        Assert.Equal(HttpStatusCode.NoContent, finalDecision.StatusCode);
        using var granted = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        Assert.Equal(2, asserter.Calls);
        using var replay = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConsentCodeIsCanonicalAndDistinctFromPendingId(bool personServer)
    {
        await using var fixture = await Fixture.CreateAsync("interaction", new ConsentAsserter(IdentityAssertion.NeedsConsent()));
        using var initial = personServer
            ? await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") })
            : await fixture.Ps.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read"), agent_token = fixture.AgentToken });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues("AAuth-Requirement").Single()))!;
        Assert.NotEqual(initial.Headers.Location!.ToString().Split('/').Last(), interaction.Code);
        Assert.All(interaction.Code!, symbol => Assert.Contains(symbol, InteractionCode.Alphabet));
    }

    [Theory]
    [InlineData("parent")]
    [InlineData("child-key")]
    [InlineData("child-agent")]
    [InlineData("upstream-audience")]
    [InlineData("upstream-trust")]
    [InlineData("mission-missing")]
    [InlineData("mission-approver")]
    [InlineData("mission-hash")]
    public async Task CombinedFederationRejectsMismatchedVerifiedContext(string variant)
    {
        await using var fixture = await Fixture.CreateAsync("immediate");
        var childKey = AAuthKey.Generate();
        const string parent = "aauth:demo@ap.test";
        const string child = "aauth:demo+worker@ap.test";
        var childToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.test", Subject = child, ParentAgent = parent, Key = fixture.ApKey, KeyId = "key", ConfirmationKey = childKey,
        }.Build();
        if (variant == "parent")
        {
            var payload = Payload(childToken);
            payload["parent_agent"] = "aauth:other@ap.test";
            payload["sub"] = "aauth:other+worker@ap.test";
            childToken = JwtWriter.SignCompact(new JsonObject { ["alg"] = "Ed25519", ["typ"] = AgentTokenBuilder.TokenType, ["kid"] = "key" }, payload, fixture.ApKey);
        }
        var mission = variant.StartsWith("mission", StringComparison.Ordinal)
            ? new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null;
        var upstream = new AuthTokenBuilder
        {
            Issuer = variant == "upstream-trust" ? "https://other-resource.test" : Fixture.PsIssuer,
            Audience = variant == "upstream-audience" ? "https://other.test" : "https://ap.test",
            Agent = "aauth:original@origin.test", AgentConfirmationKey = AAuthKey.Generate(),
            Key = variant == "upstream-trust" ? fixture.ResourceKey : fixture.PsKey, KeyId = "key",
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2), Scope = "upstream.read", Mission = mission,
        }.Build();
        var resource = new ResourceTokenBuilder
        {
            Issuer = "https://resource.test", Audience = "https://as.test",
            Agent = variant == "child-agent" ? parent : child,
            AgentJkt = (variant == "child-key" ? fixture.AgentKey : childKey).ComputeJwkThumbprint(),
            Key = fixture.ResourceKey, KeyId = "key", Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource,
            Mission = variant switch
            {
                "mission-missing" => null,
                "mission-approver" => new MissionClaim("https://other-ps.test", mission!.S256),
                "mission-hash" => new MissionClaim(Fixture.PsIssuer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                _ => mission,
            },
        }.Build();
        using var result = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = resource, subagent_token = childToken, upstream_token = upstream });
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null(fixture.Policy.Last);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(true, true, true)]
    public async Task FourPartyUsesDistinctChildKeyAndExactUpstreamChain(bool child, bool upstream, bool governed = false)
    {
        await using var fixture = await Fixture.CreateAsync("claims", missionConsent: new MissionConsent(MissionTokenConsentDecision.Grant()));
        var childKey = AAuthKey.Generate();
        var upstreamKey = AAuthKey.Generate();
        const string childId = "aauth:demo+worker@ap.test";
        var mission = governed ? new MissionClaim(Fixture.PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null;
        if (mission is not null) await fixture.PersonApp.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            mission.S256, mission.Approver, "aauth:root@root.test", ReadOnlyMemory<byte>.Empty));
        var childToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.test", Subject = childId, ParentAgent = "aauth:demo@ap.test",
            Key = fixture.ApKey, KeyId = "key", ConfirmationKey = childKey, Lifetime = TimeSpan.FromMinutes(2),
        }.Build();
        var upstreamToken = new AuthTokenBuilder
        {
            Issuer = Fixture.PsIssuer, Audience = "https://ap.test", Agent = "aauth:original@origin.test",
            Key = fixture.PsKey, KeyId = "key", AgentConfirmationKey = upstreamKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1), Subject = "upstream-only-person", Scope = "unrelated.scope",
            Act = new JsonObject { ["agent"] = "aauth:root@root.test" },
            Mission = mission,
        }.Build();
        var resourceToken = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            Issuer = "https://resource.test", Audience = "https://as.test", Agent = child ? childId : "aauth:demo@ap.test",
            AgentJkt = (child ? childKey : fixture.AgentKey).ComputeJwkThumbprint(), Key = fixture.ResourceKey, KeyId = "key", Scope = "read",
            Mission = mission,
        }.Build();
        using var result = await fixture.Agent.PostAsJsonAsync("/token", new
        {
            resource_token = resourceToken, subagent_token = child ? childToken : null, upstream_token = upstream ? upstreamToken : null,
        });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        var auth = Payload((await result.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!.GetValue<string>());
        Assert.Equal(child ? childId : "aauth:demo@ap.test", (string?)auth["agent"]);
        Assert.Equal((child ? childKey : fixture.AgentKey).ComputeJwkThumbprint(), KeyFactory.FromPublicJwk(auth["cnf"]!["jwk"]!.AsObject()).ComputeJwkThumbprint());
        var expected = new List<string>();
        if (child) expected.Add("aauth:demo@ap.test");
        if (upstream) expected.AddRange(["aauth:original@origin.test", "aauth:root@root.test"]);
        Assert.Equal(expected, ActChainReader.GetDelegationChain(auth));
        Assert.NotEqual("upstream-only-person", (string?)auth["sub"]);
        Assert.True(JsonNode.DeepEquals(mission?.ToJsonObject(), auth["mission"]));
        if (upstream) Assert.True((long)auth["exp"]! <= (long)Payload(upstreamToken)["exp"]!);
        if (child) Assert.True((long)auth["exp"]! <= (long)Payload(childToken)["exp"]!);
    }

    [Theory]
    [InlineData("immediate")]
    [InlineData("interaction")]
    [InlineData("claims")]
    public async Task PsDenialPreventsGrantWithoutAsClaimsRequest(string outcome)
    {
        var asserter = new ConsentAsserter(IdentityAssertion.Deny("PS consent denied"));
        await using var fixture = await Fixture.CreateAsync(outcome, asserter);
        using var result = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") });
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        Assert.Equal("denied", (await result.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        Assert.Equal(1, asserter.Calls);
        Assert.Null(fixture.Policy.Last);
    }

    [Theory]
    [InlineData("immediate", true)]
    [InlineData("interaction", true)]
    [InlineData("claims", true)]
    [InlineData("immediate", false)]
    [InlineData("interaction", false)]
    [InlineData("claims", false)]
    public async Task PsConsentSuspendsFederationUntilAuthenticatedDecision(string outcome, bool approve)
    {
        var asserter = new ConsentAsserter(IdentityAssertion.NeedsConsent());
        await using var fixture = await Fixture.CreateAsync(outcome, asserter);
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Contains("https://ps.test/interaction", initial.Headers.GetValues("AAuth-Requirement").Single());
        Assert.Null(fixture.Policy.Last);
        using var held = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, held.StatusCode);
        using var browser = fixture.PersonApp.GetTestClient();
        browser.BaseAddress = new Uri(Fixture.PsIssuer);
        using var unsignedDecision = await browser.PostAsync("/interaction/approve", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = initial.Headers.Location!.ToString().Split('/').Last() }));
        Assert.Equal(HttpStatusCode.Unauthorized, unsignedDecision.StatusCode);
        asserter.Verdict = IdentityAssertion.Assert("directed-resource-person");
        using var decision = await TestConsentBrowser.DecideAsync(browser,
            "/interaction?code=" + Interaction.FromRequirement(AAuthRequirementHeader.Parse(initial.Headers.GetValues("AAuth-Requirement").Single()))!.Code,
            "/interaction/" + (approve ? "approve" : "deny"));
        Assert.Equal(HttpStatusCode.NoContent, decision.StatusCode);
        if (approve && outcome == "interaction")
        {
            for (var attempt = 0; attempt < 100 && fixture.Store.Last is null; attempt++) await Task.Delay(10);
            Assert.NotNull(fixture.Store.Last);
            using var waiting = await fixture.Agent.GetAsync(initial.Headers.Location);
            Assert.Equal(HttpStatusCode.Accepted, waiting.StatusCode);
            fixture.Store.MarkAllowed(fixture.AsEntry.Id);
        }
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(approve ? HttpStatusCode.OK : HttpStatusCode.Forbidden, result.StatusCode);
        if (!approve) Assert.Null(fixture.Policy.Last);
        if (approve && outcome == "claims")
            Assert.Equal("directed-resource-person", fixture.Policy.Last!.Claims!["sub"]!.GetValue<string>());
        using var replay = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedClaimsConsentNeverBecomesClaims(bool needsConsent)
    {
        var asserter = new ConsentAsserter(IdentityAssertion.Assert("approved"))
        {
            ClaimsVerdict = needsConsent ? IdentityAssertion.NeedsConsent() : IdentityAssertion.Deny("no claims release"),
        };
        await using var fixture = await Fixture.CreateAsync("claims", asserter);
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken("read") });
        Assert.Equal(needsConsent ? HttpStatusCode.Accepted : HttpStatusCode.Forbidden, initial.StatusCode);
        Assert.Null(fixture.AsEntry.SuppliedClaims);
        Assert.Equal(2, asserter.Calls);
        if (needsConsent)
        {
            using var cancel = await fixture.Agent.DeleteAsync(initial.Headers.Location);
            Assert.Equal(HttpStatusCode.NoContent, cancel.StatusCode);
        }
    }

    private sealed class ConsentAsserter(IdentityAssertion verdict) : IIdentityClaimsAsserter
    {
        public IdentityAssertion Verdict { get; set; } = verdict;
        public IdentityAssertion? ClaimsVerdict { get; init; }
        public int Calls { get; private set; }
        public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(request.RequiredClaims is not null ? ClaimsVerdict ?? Verdict : Verdict);
        }
    }

    [Theory]
    [InlineData("answer")]
    [InlineData("update")]
    [InlineData("deny")]
    [InlineData("cancel")]
    [InlineData("claims")]
    public async Task ProductionPsRelaysClarificationAndResumes(string outcome)
    {
        await using var fixture = await Fixture.CreateAsync(outcome);
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken() });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.Equal("requirement=clarification", initial.Headers.GetValues("AAuth-Requirement").Single());
        if (outcome == "cancel")
        {
            using var cancel = await fixture.Agent.DeleteAsync(initial.Headers.Location);
            Assert.Equal(HttpStatusCode.NoContent, cancel.StatusCode);
            using var cancelled = await fixture.Agent.GetAsync(initial.Headers.Location);
            Assert.Equal(HttpStatusCode.Gone, cancelled.StatusCode);
            for (var attempt = 0; attempt < 100 && !fixture.AsEntry.Lifecycle.Cancelled; attempt++) await Task.Delay(10);
            Assert.True(fixture.AsEntry.Lifecycle.Cancelled);
            return;
        }
        using var answer = await fixture.Agent.PostAsJsonAsync(initial.Headers.Location, outcome == "update"
            ? new JsonObject { ["action"] = "updated_request", ["resource_token"] = fixture.ResourceToken("read") }
            : new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = "requested by the user" });
        Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
        using var result = await PollAsync(fixture.Agent, initial.Headers.Location!);
        Assert.Equal(outcome == "deny" ? HttpStatusCode.Forbidden : HttpStatusCode.OK, result.StatusCode);
        if (outcome != "deny")
        {
            var payload = Payload((await result.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!.GetValue<string>());
            Assert.Equal(outcome == "update" ? "read" : "read write", payload["scope"]!.GetValue<string>());
            Assert.Equal(outcome == "update" ? "read" : "read write", fixture.Policy.Last!.Scope);
        }
        using var replay = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
        Assert.True(fixture.AsEntry.Lifecycle.Delivered);
    }

    [Theory]
    [InlineData("GET", false)]
    [InlineData("POST", false)]
    [InlineData("DELETE", false)]
    [InlineData("GET", true)]
    [InlineData("POST", true)]
    [InlineData("DELETE", true)]
    public async Task AsPendingRejectsForeignPsAndChangedPsKey(string method, bool sameIssuer)
    {
        await using var fixture = await Fixture.CreateAsync("answer");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken(),
        });
        using var foreign = fixture.PsClient(sameIssuer ? Fixture.PsIssuer : "https://other-ps.test", "second");
        using var request = new HttpRequestMessage(new HttpMethod(method), initial.Headers.Location);
        if (method == "POST") request.Content = JsonContent.Create(new { action = "clarification_response", clarification_response = "approve" });
        using var response = await foreign.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var owner = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, owner.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("unknown")]
    [InlineData("updated_request")]
    public async Task AsClarificationRequiresMatchingAction(string? action)
    {
        await using var fixture = await Fixture.CreateAsync("answer");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken(),
        });
        using var invalid = await fixture.Ps.PostAsJsonAsync(initial.Headers.Location,
            new JsonObject { ["action"] = action, ["clarification_response"] = "answer" });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("issuer")]
    [InlineData("agent")]
    [InlineData("key")]
    public async Task AsRejectsMalformedOrReboundReplacement(string variant)
    {
        await using var fixture = await Fixture.CreateAsync("update");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken(),
        });
        using var response = await fixture.Ps.PostAsJsonAsync(initial.Headers.Location, new
        {
            action = "updated_request",
            resource_token = variant == "malformed" ? "bad.jwt" : fixture.ResourceToken("read", variant),
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("read write", fixture.AsEntry.Scope);
    }

    private static async Task<HttpResponseMessage> PollAsync(HttpClient client, Uri uri)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var response = await client.GetAsync(uri);
            if (response.StatusCode != HttpStatusCode.Accepted) return response;
            response.Dispose();
            await Task.Delay(20);
        }
        throw new TimeoutException("PS relay did not complete.");
    }

    [Fact]
    public async Task PsCanTriageLocallyWithoutRelayingToAgent()
    {
        await using var fixture = await Fixture.CreateAsync("local");
        using var result = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken() });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Equal("mission context answers this", Assert.Single(fixture.Policy.Last!.ClarificationHistory));
    }

    [Fact]
    public async Task ClarificationDeadlineTerminatesBothPendingRequests()
    {
        await using var fixture = await Fixture.CreateAsync("timeout");
        using var initial = await fixture.Agent.PostAsJsonAsync("/token", new { resource_token = fixture.ResourceToken() });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        await Task.Delay(1200);
        using var expired = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.RequestTimeout, expired.StatusCode);
        using var again = await fixture.Agent.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, again.StatusCode);
        for (var attempt = 0; attempt < 100 && !fixture.AsEntry.Lifecycle.Delivered && !fixture.AsEntry.Lifecycle.Cancelled; attempt++) await Task.Delay(10);
        Assert.True(fixture.AsEntry.Lifecycle.Delivered || fixture.AsEntry.Lifecycle.Cancelled);
    }

    [Fact]
    public async Task AsEnforcesClarificationRoundLimit()
    {
        await using var fixture = await Fixture.CreateAsync("repeat");
        using var initial = await fixture.Ps.PostAsJsonAsync("/token", new { agent_token = fixture.AgentToken, resource_token = fixture.ResourceToken() });
        for (var round = 0; round < 5; round++)
        {
            using var answer = await fixture.Ps.PostAsJsonAsync(initial.Headers.Location,
                new { action = "clarification_response", clarification_response = "answer" });
            Assert.Equal(HttpStatusCode.NoContent, answer.StatusCode);
            using var poll = await fixture.Ps.GetAsync(initial.Headers.Location);
            Assert.Equal(round == 4 ? HttpStatusCode.Forbidden : HttpStatusCode.Accepted, poll.StatusCode);
        }
        using var replay = await fixture.Ps.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    private static JsonObject Payload(string jwt) => JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!.AsObject();

    private sealed class Policy(string outcome) : IAccessPolicy
    {
        public AccessPolicyRequest? Last { get; private set; }
        public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default)
        {
            Last = request;
            if (outcome == "reconsent") return Task.FromResult(request.InteractionId is not null && request.ClarificationHistory.Count == 0
                ? AccessDecision.NeedsClarification("Review the request", 30) : AccessDecision.NeedsInteraction());
            if (outcome == "interaction") return Task.FromResult(AccessDecision.NeedsInteraction());
            if (outcome == "repeat" || (request.ClarificationHistory.Count == 0 && request.Scope != "read"))
                return Task.FromResult(AccessDecision.NeedsClarification("Why this scope?", outcome == "timeout" ? 1 : 30));
            if (outcome == "deny") return Task.FromResult(AccessDecision.Deny("declined"));
            if (outcome == "claims" && request.Claims?["sub"] is null)
                return Task.FromResult(AccessDecision.NeedsClaims(["sub"]));
            return Task.FromResult(AccessDecision.Allow("user"));
        }
    }

    private sealed class Store : IAccessPendingStore
    {
        private readonly InMemoryAccessPendingStore _inner = new();
        public AccessPendingEntry? Last;
        public AccessPendingEntry Add(string resourceUrl, string scope, string agentId, IAAuthKey key, DateTimeOffset expiry,
            JsonObject? claims, IReadOnlyList<string>? requiredClaims = null, DateTimeOffset? authorizationExpiresAt = null, JsonObject? upstreamAct = null)
            => Last = _inner.Add(resourceUrl, scope, agentId, key, expiry, claims, requiredClaims, authorizationExpiresAt, upstreamAct);
        public AccessPendingEntry? Get(string id) => _inner.Get(id);
        public AccessPendingEntry? GetByCode(string code) => _inner.GetByCode(code);
        public void Clear() => _inner.Clear();
        public void MarkAllowed(string id) => _inner.MarkAllowed(id);
        public void MarkDenied(string id, string reason) => _inner.MarkDenied(id, reason);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        public const string PsIssuer = "https://ps.test";
        private const string AsIssuer = "https://as.test";
        private const string AgentId = "aauth:demo@ap.test";
        public required WebApplication PersonApp;
        public required WebApplication AccessApp;
        public required HttpClient Agent;
        public required HttpClient Ps;
        public required AAuthKey AgentKey;
        public required AAuthKey ResourceKey;
        public required AAuthKey SecondPsKey;
        public required AAuthKey ApKey;
        public required AAuthKey PsKey;
        public required AAuthKey AsKey;
        public required string AgentToken;
        public required Policy Policy;
        public required Store Store;
        public required Discovery DiscoveryTransport;
        public required Logs Logs { get; init; }
        public DirectCapture? DirectRequest;
        public AccessPendingEntry AsEntry => Store.Last!;

        public string UpstreamToken(string? variant = null) => new AuthTokenBuilder
        {
            Issuer = variant == "upstream-issuer" ? PsIssuer : AsIssuer,
            Dwk = variant == "upstream-issuer" ? AuthTokenBuilder.PersonDwk : AuthTokenBuilder.AccessDwk,
            Audience = variant == "upstream-audience" ? "https://other.test" : "https://ap.test",
            Agent = "aauth:original@origin.test", Subject = "upstream-person", Scope = "upstream.read",
            Key = variant == "upstream-issuer" ? PsKey : AsKey, KeyId = "key", AgentConfirmationKey = AAuthKey.Generate(),
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            Mission = variant == "mission" ? new MissionClaim(PsIssuer, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null,
        }.Build();

        public HttpClient DirectClient()
        {
            DirectRequest = new DirectCapture { InnerHandler = AccessApp.GetTestServer().CreateHandler() };
            var client = new AAuthClientBuilder(AgentKey).UseJwt(AgentToken).WithEgressPolicy(TestEgress.Policy)
                .WithInnerHandler(DirectRequest, AAuthTransportContract.InProcessOnly).Build();
            client.BaseAddress = new Uri(AsIssuer);
            return client;
        }

        public string ResourceToken(string scope = "read write", string? variant = null, MissionClaim? mission = null, string? account = null) => new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            Issuer = variant == "issuer" ? "https://other-resource.test" : "https://resource.test",
            Audience = AsIssuer,
            Agent = variant == "agent" ? "aauth:other@ap.test" : AgentId,
            AgentJkt = (variant == "key" ? AAuthKey.Generate() : AgentKey).ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = "key",
            Scope = scope,
            Mission = mission,
            Account = account,
        }.Build();

        public HttpClient PsClient(string issuer, string kid)
        {
            var client = new AAuthClientBuilder(SecondPsKey)
                .UseJwksUri(issuer, AAuthConstants.DwkFiles.Person, kid).WithEgressPolicy(TestEgress.Policy)
                .WithInnerHandler(AccessApp.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
            client.BaseAddress = new Uri(AsIssuer);
            return client;
        }

        public static async Task<Fixture> CreateAsync(string outcome, IIdentityClaimsAsserter? asserter = null, IMissionTokenConsent? missionConsent = null)
        {
            var psKey = AAuthKey.Generate();
            var secondPsKey = AAuthKey.Generate();
            var resourceKey = AAuthKey.Generate();
            var apKey = AAuthKey.Generate();
            var asKey = AAuthKey.Generate();
            var agentKey = AAuthKey.Generate();
            var keys = new Dictionary<string, AAuthKey>
            {
                [PsIssuer] = psKey,
                [AsIssuer] = asKey,
                ["https://ap.test"] = apKey,
                ["https://resource.test"] = resourceKey,
                ["https://other-resource.test"] = resourceKey,
                ["https://other-ps.test"] = secondPsKey,
            };
            var discoveryTransport = new Discovery(keys, secondPsKey);
            var discovery = new InProcessHttpClient(discoveryTransport);
            var metadata = new MetadataClient(discovery);
            var jwks = new JwksClient(discovery);
            var store = new Store();
            var policy = new Policy(outcome);
            var accessBuilder = WebApplication.CreateBuilder();
            accessBuilder.WebHost.UseTestServer();
            accessBuilder.Services.AddSingleton(metadata).AddSingleton(jwks).AddSingleton(new TokenVerifier())
                .AddSingleton(new AAuthVerifier()).AddSingleton<IAccessPolicy>(policy).AddSingleton<IAccessPendingStore>(store);
            var access = accessBuilder.Build();
            if (outcome == "unstructured-error") access.Use(async (context, next) =>
            {
                if (context.Request.Path != "/token") { await next(); return; }
                context.Response.StatusCode = 502;
                await context.Response.WriteAsync("TOKEN-SECRET-SENTINEL person-sentinel@example.test\nforged-log-line");
            });
            access.MapAAuthAccessServer(new AAuthAccessServerOptions { Issuer = AsIssuer, SigningKeys = new Dictionary<string, IAAuthKey> { ["key"] = asKey } });
            var accessSessions = new BrowserConsentSessions("as-consent-tests", "test-person", isolatedDemoAccess: _ => true);
            access.MapMethods("/interaction/login", ["GET", "POST"], async (HttpContext context) =>
            {
                var arrival = await accessSessions.EnterAsync(context, code => store.GetByCode(code) is { } entry
                    ? new BrowserPendingRequest(entry.Id, entry.PendingExpiresAt, entry.Browser, entry.Lifecycle) : null);
                return arrival.Error ?? Results.Content(accessSessions.Fields(context, arrival.Decision!), "text/html");
            });
            access.MapPost("/interaction/approve", async (HttpContext context) =>
            {
                var decision = await accessSessions.DecideAsync(context);
                if (decision.Error is not null) return decision.Error;
                var entry = store.Get(decision.Decision!.Id)!;
                return await decision.Decision.ApplyAsync(context, () =>
                {
                    if (entry.Status != AccessPendingStatus.Pending) return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                    entry.Status = outcome == "reconsent" && entry.ClarificationAnswers.Count == 0
                        ? AccessPendingStatus.Review : AccessPendingStatus.Allowed;
                    return Results.NoContent();
                });
            });
            await access.StartAsync();
            var ps = new AAuthClientBuilder(psKey).UseJwksUri(PsIssuer, AAuthConstants.DwkFiles.Person, "key")
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(access.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
            ps.BaseAddress = new Uri(AsIssuer);
            var personBuilder = WebApplication.CreateBuilder();
            personBuilder.WebHost.UseTestServer();
            var logs = new Logs();
            personBuilder.Logging.AddProvider(logs);
            personBuilder.Services.AddSingleton(metadata).AddSingleton(jwks).AddSingleton(new TokenVerifier())
                .AddSingleton(new AAuthVerifier()).AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>()
                .AddSingleton<IIdentityClaimsAsserter>(asserter ?? new DefaultIdentityClaimsAsserter("user"))
                .AddSingleton(new AccessServerClient(ps, metadata, new AuthTokenResponseValidator(metadata, jwks)));
            personBuilder.Services.AddAAuthGovernance();
            if (missionConsent is not null) personBuilder.Services.AddSingleton(missionConsent);
            var person = personBuilder.Build();
            person.MapAAuthPersonServer(new AAuthPersonServerOptions
            {
                Issuer = PsIssuer,
                ResourceInteractionSessions = new BrowserConsentSessions("resource-consent-tests", "test-person", isolatedDemoAccess: _ => true),
                SigningKeys = new Dictionary<string, IAAuthKey> { ["key"] = psKey },
                TriageClarificationAsync = outcome == "local"
                    ? (_, _, _) => Task.FromResult<ClarificationResponse?>(ClarificationResponse.Respond("mission context answers this")) : null,
            });
            var sessions = new BrowserConsentSessions("consent-tests", "authenticated-demo-person", isolatedDemoAccess: _ => true);
            var personStore = person.Services.GetRequiredService<IPersonPendingStore>();
            person.MapMethods("/interaction", ["GET", "POST"], async (HttpContext context) =>
            {
                var arrival = await sessions.EnterAsync(context, code => personStore.GetByCode(code) is { } entry
                    ? new BrowserPendingRequest(entry.Id, entry.PendingExpiresAt, entry.Browser, entry.Lifecycle) : null);
                return arrival.Error ?? Results.Content(sessions.Fields(context, arrival.Decision!), "text/html");
            });
            foreach (var action in new[] { "approve", "deny" })
                person.MapPost("/interaction/" + action, async (HttpContext context) =>
                {
                    var decision = await sessions.DecideAsync(context);
                    if (decision.Error is not null) return decision.Error;
                    var entry = personStore.Get(decision.Decision!.Id)!;
                    return await decision.Decision.ApplyAsync(context, () =>
                    {
                        if (entry.Status != PersonPendingStatus.Pending) return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                        if (action == "approve")
                        {
                            entry.Subject = "directed-resource-person";
                            if (entry.FederationConsent is { } consent) consent.TrySetResult(IdentityAssertion.Assert(entry.Subject));
                            else entry.Status = PersonPendingStatus.Allowed;
                        }
                        else
                        {
                            entry.Status = PersonPendingStatus.Denied;
                            entry.DenyReason = "person denied";
                            entry.FederationConsent?.TrySetResult(IdentityAssertion.Deny(entry.DenyReason));
                        }
                        return Results.NoContent();
                    });
                }).DisableAntiforgery();
            await person.StartAsync();
            var agentToken = new AgentTokenBuilder
            { Issuer = "https://ap.test", Subject = AgentId, Key = apKey, KeyId = "key", ConfirmationKey = agentKey }.Build();
            var agent = new AAuthClientBuilder(agentKey).UseJwt(agentToken).WithEgressPolicy(TestEgress.Policy)
                .WithInnerHandler(person.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
            agent.BaseAddress = new Uri(PsIssuer);
            return new Fixture
            {
                PersonApp = person,
                AccessApp = access,
                Agent = agent,
                Ps = ps,
                AgentKey = agentKey,
                AgentToken = agentToken,
                ResourceKey = resourceKey,
                SecondPsKey = secondPsKey,
                ApKey = apKey,
                PsKey = psKey,
                AsKey = asKey,
                Policy = policy,
                Store = store,
                DiscoveryTransport = discoveryTransport,
                Logs = logs,
            };
        }

        public async ValueTask DisposeAsync()
        {
            Agent.Dispose(); Ps.Dispose(); await PersonApp.DisposeAsync(); await AccessApp.DisposeAsync();
        }
    }

    private sealed class Discovery(Dictionary<string, AAuthKey> keys, AAuthKey second) : HttpMessageHandler
    {
        public System.Collections.Concurrent.ConcurrentBag<string> Paths { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsoluteUri);
            var origin = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            if (origin == "https://as.test" && request.RequestUri.AbsolutePath == "/.well-known/aauth-person.json")
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            JsonObject body;
            if (request.RequestUri.AbsolutePath.EndsWith("jwks.json", StringComparison.Ordinal))
            {
                var primary = keys[origin].ToPublicJwk(); primary["kid"] = "key";
                var alternate = second.ToPublicJwk(); alternate["kid"] = "second";
                body = new JsonObject { ["keys"] = new JsonArray(primary, alternate) };
            }
            else body = new JsonObject { ["issuer"] = origin, ["jwks_uri"] = origin + "/.well-known/jwks.json", ["token_endpoint"] = origin + "/token" };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(body) });
        }
    }

    private sealed class DirectCapture : DelegatingHandler
    {
        public string? Scheme;
        public JsonObject? Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                Scheme = SignatureKeyParser.ParseAny(request.Headers.GetValues("Signature-Key").Single()).Scheme;
                Body = await request.Content!.ReadFromJsonAsync<JsonObject>(cancellationToken);
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }
}