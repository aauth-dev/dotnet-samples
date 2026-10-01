using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Conformance.Discovery;

public class RevocationLifecycleTests
{
    [Fact]
    public async Task ThreeGenerationsRevokeAndNotifyAllLocalDescendants()
    {
        await using var graph = await Graph.CreateAsync();
        var first = await graph.AgentTokenAsync(FirstProvider, "original");
        var second = await graph.AgentTokenAsync(FirstResource, "intermediary-one", distinctKey: true);
        var third = await graph.AgentTokenAsync(SecondResource, "intermediary-two", distinctKey: true);
        var root = await graph.GrantAsync(first, FirstResource, false);
        var child = await graph.GrantAsync(second, SecondResource, false, root);
        var grandchild = await graph.GrantAsync(third, FirstResource, false, child);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(child, SecondResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(grandchild, FirstResource));
        using var issuer = graph.Signed(Person, AuthTokenBuilder.PersonDwk);
        Assert.Equal(HttpStatusCode.OK, (await Revoke(issuer, Person, root)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(child, SecondResource));
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(grandchild, FirstResource));
        Assert.Contains(graph.Revocations, entry => entry.Token.TokenId == (string?)Decode(child)["jti"]);
        Assert.Contains(graph.Revocations, entry => entry.Token.TokenId == (string?)Decode(grandchild)["jti"]);
        using var extension = await graph.RequestAsync(second, SecondResource, false, grandchild);
        // §Upstream Token Verification / §Token Endpoint Error Codes: a revoked upstream token is 400 revoked_upstream_token.
        var extensionBody = await extension.Content.ReadAsStringAsync();
        Assert.True(extension.StatusCode == HttpStatusCode.BadRequest, $"Status={(int)extension.StatusCode} {extensionBody}");
        Assert.Contains("revoked_upstream_token", extensionBody);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LocallyRevokedUpstreamCannotBeExtended(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var upstream = await graph.GrantAsync(agent, FirstProvider, false);
        using var issuer = graph.Signed(Person, AuthTokenBuilder.PersonDwk);
        Assert.Equal(HttpStatusCode.OK, (await Revoke(issuer, Person, upstream)).StatusCode);
        using var blocked = await graph.RequestAsync(agent, FirstResource, federated, upstream);
        var blockedBody = await blocked.Content.ReadAsStringAsync();
        Assert.True(blocked.StatusCode == HttpStatusCode.BadRequest, $"Status={(int)blocked.StatusCode} {blockedBody}");
        var blockedJson = JsonNode.Parse(blockedBody)!.AsObject();
        Assert.Equal("revoked_upstream_token", (string?)blockedJson["error"]);
        Assert.False(blockedJson.ContainsKey("auth_token"));
    }

    [Fact]
    public async Task UpstreamRevokedDuringConsentCannotMintAfterApproval()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var upstream = await graph.GrantAsync(agent, FirstProvider, false);
        graph.Consent.Required = true;
        using var initial = await graph.RequestAsync(agent, FirstResource, false, upstream);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        using var issuer = graph.Signed(Person, AuthTokenBuilder.PersonDwk);
        Assert.Equal(HttpStatusCode.OK, (await Revoke(issuer, Person, upstream)).StatusCode);
        graph.Pending.MarkAllowed(initial.Headers.Location!.ToString().Split('/').Last(), new AAuthPersonKey("person"), "person");
        using var client = graph.AgentClient(agent);
        using var result = await client.GetAsync(Person + initial.Headers.Location);
        // §Polling Error Codes: a pending request whose upstream token was revoked is 403 revoked.
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        var body = (await result.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal("revoked", (string?)body["error"]);
        Assert.Contains("upstream", (string?)body["detail"], StringComparison.OrdinalIgnoreCase);
        Assert.False(body.ContainsKey("auth_token"));
    }

    [Fact]
    public async Task FourPartyApproval_DoesNotFederateRevokedPresentedToken()
    {
        await using var graph = await Graph.CreateAsync(consent: true);
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var personToken = await graph.PersonTokenAsync(agent, FirstResource);
        using var initial = await graph.RequestAsync(agent, FirstResource, federated: true, personToken: personToken);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);

        using var ps = graph.Signed(Person, AuthTokenBuilder.PersonDwk);
        Assert.Equal(HttpStatusCode.OK, (await Revoke(ps, Person, personToken)).StatusCode);
        graph.Pending.MarkAllowed(initial.Headers.Location!.ToString().Split('/').Last(), new AAuthPersonKey("person"), "person");

        using var client = graph.AgentClient(agent);
        using var result = await client.GetAsync(Person + initial.Headers.Location);

        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        var body = (await result.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal("revoked", (string?)body["error"]);
        Assert.Contains("presented", (string?)body["detail"], StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, graph.AccessTokenRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpstreamRevocationCascadesToDownstreamGrant(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var upstream = await graph.GrantAsync(agent, FirstProvider, false);
        var grant = await graph.GrantAsync(agent, FirstResource, federated, upstream);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(grant, FirstResource));
        using var issuer = graph.Signed(Person, AuthTokenBuilder.PersonDwk);
        var revoked = await Revoke(issuer, Person, upstream);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Empty(revoked.Downstream);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(grant, FirstResource));
        // Four-party: the PS revokes its upstream token at the AS, which revokes its own grant.
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(federated ? Access : Person, (string)Decode(grant)["jti"]!));
    }

    [Theory(DisplayName = "§Upstream Token Verification step 4 — an upstream token from a revoked calling agent is revoked_upstream_token")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpstreamFromRevokedCallingAgent_IsRevokedUpstreamToken(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var caller = await graph.AgentTokenAsync(FirstProvider, "caller");
        var intermediary = await graph.AgentTokenAsync(FirstResource, "intermediary", distinctKey: true);
        var upstream = await graph.GrantAsync(caller, FirstResource, false);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(upstream, FirstResource));
        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        Assert.Equal(HttpStatusCode.OK, (await Revoke(ap, Person, caller)).StatusCode);

        using var blocked = await graph.RequestAsync(intermediary, SecondResource, federated, upstream);

        var body = await blocked.Content.ReadAsStringAsync();
        Assert.True(blocked.StatusCode == HttpStatusCode.BadRequest, $"Status={(int)blocked.StatusCode} {body}");
        Assert.Equal("revoked_upstream_token", (string?)JsonNode.Parse(body)!["error"]);
    }

    [Theory(DisplayName = "§Upstream Token Verification step 4 — a revoked agent-person binding makes the upstream token revoked_upstream_token and survives agent-token refresh")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpstreamFromRevokedBinding_IsRevokedUpstreamToken(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var caller = await graph.AgentTokenAsync(FirstProvider, "caller");
        var intermediary = await graph.AgentTokenAsync(FirstResource, "intermediary", distinctKey: true);
        var upstream = await graph.GrantAsync(caller, FirstResource, false);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(upstream, FirstResource));

        await AgentPersonBinding.RevokeAsync(graph.PersonInventory, graph.Bindings,
            Person, FirstProvider, "aauth:demo@first-ap.example");

        // The agent token itself is not revoked; only the binding is.
        using var blocked = await graph.RequestAsync(intermediary, SecondResource, federated, upstream);
        var body = await blocked.Content.ReadAsStringAsync();
        Assert.True(blocked.StatusCode == HttpStatusCode.BadRequest, $"Status={(int)blocked.StatusCode} {body}");
        Assert.Equal("revoked_upstream_token", (string?)JsonNode.Parse(body)!["error"]);
        // A refreshed agent token (new jti) for the same agent can establish a new binding.
        using var refreshed = await graph.RequestAsync(await graph.AgentTokenAsync(FirstProvider, "caller-refreshed"), SecondResource, federated);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        // Another agent at the same provider is unaffected.
        var other = await graph.AgentTokenAsync(SecondProvider, "other");
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(await graph.GrantAsync(other, SecondResource, federated), SecondResource));
    }

    [Fact(DisplayName = "§Token Revocation — a PS whose cascade outlasts its hold answers 202 and the revoker polls its pending URL to 200")]
    public async Task SlowDownstream_PersonServerDefersAndCompletesOnPoll()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "slow-agent");
        await graph.GrantAsync(agent, FirstResource, false);
        graph.Failing[FirstResource] = "slow";
        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        using var request = new HttpRequestMessage(HttpMethod.Post, Person + "/revoke")
        {
            Content = JsonContent.Create(new JsonObject { ["jti"] = "slow-agent", ["exp"] = (long)Decode(agent)["exp"]! }),
        };
        request.Options.Set(AAuth.HttpSig.AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]);

        var response = await ap.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var pendingUrl = new Uri(new Uri(Person), response.Headers.Location!);
        for (var attempt = 0; response.StatusCode == HttpStatusCode.Accepted && attempt < 20; attempt++)
        {
            response.Dispose();
            response = await ap.GetAsync(pendingUrl);
        }
        Assert.True(response.StatusCode == HttpStatusCode.OK,
            $"{(int)response.StatusCode} {response.Headers} {await response.Content.ReadAsStringAsync()}");
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource);
        response.Dispose();
    }

    internal const string Person = "https://person.example";
    internal const string Access = "https://access.example";
    internal const string FirstProvider = "https://first-ap.example";
    internal const string SecondProvider = "https://second-ap.example";
    internal const string FirstResource = "https://first-resource.example";
    internal const string SecondResource = "https://second-resource.example";
    private const string Agent = "aauth:demo@agent.example";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProviderRevoke_BlocksSourceAndCascadesExactIssuedOrProvidedGrants(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var first = await graph.AgentTokenAsync(FirstProvider, "same-id");
        var second = await graph.AgentTokenAsync(SecondProvider, "same-id");
        var firstPerson = await graph.IssuePersonTokenAsync(first, FirstResource);
        var secondPerson = await graph.IssuePersonTokenAsync(first, SecondResource);
        var firstGrant = await graph.GrantAsync(first, FirstResource, federated, personToken: firstPerson);
        var secondGrant = await graph.GrantAsync(first, SecondResource, federated, personToken: secondPerson);
        var foreignGrant = await graph.GrantAsync(second, FirstResource, federated);
        var grantIssuer = federated ? Access : Person;
        Assert.Equal(grantIssuer, (string?)Decode(firstGrant)["iss"]);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(firstGrant, FirstResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(secondGrant, SecondResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(foreignGrant, FirstResource));
        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        var revoke = new RevocationClient(ap);

        // No "not found": an unseen agent token is recorded and answered 200.
        var unseen = await revoke.RevokeAsync(new Uri(Person + "/revoke"), "unknown", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.Equal(HttpStatusCode.OK, unseen.StatusCode);
        // The body names no issuer: FirstProvider's "same-id" never reaches SecondProvider's.
        var revoked = await Revoke(ap, Person, first);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Null(revoked.Failure);
        Assert.Empty(revoked.Downstream);
        Assert.Equal(HttpStatusCode.OK, (await Revoke(ap, Person, first)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(firstGrant, FirstResource));
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(secondGrant, SecondResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(foreignGrant, FirstResource));
        using var blocked = await graph.RequestAsync(first, FirstResource, federated);
        Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
        using var allowed = await graph.RequestAsync(second, FirstResource, federated);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);

        TokenKey Key(string issuer, string token) => new(issuer, (string)Decode(token)["jti"]!);
        // Each grant is revoked by its own issuer at its resource, once per (idempotent) revocation.
        Assert.Equal(2, graph.Revocations.Count(entry => entry.Resource == FirstResource && entry.Token == Key(grantIssuer, firstGrant)));
        Assert.Equal(2, graph.Revocations.Count(entry => entry.Resource == SecondResource && entry.Token == Key(grantIssuer, secondGrant)));
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource && entry.Token == Key(Person, firstPerson));
        Assert.Contains(graph.Revocations, entry => entry.Resource == SecondResource && entry.Token == Key(Person, secondPerson));
        Assert.DoesNotContain(graph.Revocations, entry => entry.Token.TokenId == (string?)Decode(foreignGrant)["jti"]);
        Assert.All(graph.Revocations, entry => Assert.Contains(entry.Token.Issuer, new[] { Person, grantIssuer }));
    }

    [Fact(DisplayName = "§Mission Approval / §Token Revocation — revoking the agent token revokes the person tokens its mission approval issued")]
    public async Task ProviderRevoke_CascadesToMissionApprovalPersonTokens()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "mission-agent");
        using var client = graph.AgentClient(agent);
        using var approval = await client.PostAsJsonAsync(Person + "/mission",
            new { description = "Plan the offsite", resources = new[] { FirstResource } });
        Assert.True(approval.StatusCode == HttpStatusCode.OK, await approval.Content.ReadAsStringAsync());
        var mission = AAuth.Agent.Mission.FromApprovalResponse(await approval.Content.ReadAsByteArrayAsync(), Person);
        var personToken = mission.PersonTokens[FirstResource];

        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        Assert.Equal(HttpStatusCode.OK, (await Revoke(ap, Person, agent)).StatusCode);

        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(Person, (string)Decode(personToken)["jti"]!));
        // A fresh agent token under the same key cannot present the revoked person token.
        using var reused = await graph.RequestAsync(await graph.AgentTokenAsync(FirstProvider, "fresh"), FirstResource, false,
            personToken: personToken);
        var reusedBody = await reused.Content.ReadAsStringAsync();
        Assert.False(reused.IsSuccessStatusCode, reusedBody);
        Assert.DoesNotContain("auth_token", reusedBody);
    }

    [Fact]
    public async Task PendingApproval_CannotReplaceRevokedOriginalSourceWithFreshCarrier()
    {
        await using var graph = await Graph.CreateAsync(consent: true);
        var original = await graph.AgentTokenAsync(FirstProvider, "original");
        using var response = await graph.RequestAsync(original, FirstResource, false);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var pendingPath = response.Headers.Location!.ToString();
        var entry = graph.Pending.Get(pendingPath[(pendingPath.LastIndexOf('/') + 1)..])!;
        graph.Pending.MarkAllowed(entry.Id, new AAuthPersonKey("person"), "person");
        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        Assert.Equal(HttpStatusCode.OK, (await Revoke(ap, Person, original)).StatusCode);
        var fresh = await graph.AgentTokenAsync(FirstProvider, "fresh");
        using var agent = graph.AgentClient(fresh);
        using var poll = await agent.GetAsync(Person + pendingPath);
        // §Polling Error Codes: the agent token that started the request was revoked.
        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("revoked", (string?)body!["error"]);
        Assert.Contains("agent", (string?)body["detail"], StringComparison.OrdinalIgnoreCase);
        Assert.False(body.ContainsKey("auth_token"));
    }

    [Fact(DisplayName = "§Token Revocation — a resource records a grant it never saw, and refuses it when presented later")]
    public async Task UnseenResourceGrant_IsRecordedAndRefusedWhenPresented()
    {
        await using var graph = await Graph.CreateAsync();
        var source = await graph.AgentTokenAsync(FirstProvider, "unseen-grant");
        var grant = await graph.GrantAsync(source, FirstResource, false);
        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        var revoked = await Revoke(ap, Person, source);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Null(revoked.Failure);
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(Person, (string)Decode(grant)["jti"]!));
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(grant, FirstResource));
        using var blocked = await graph.RequestAsync(source, FirstResource, false);
        Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
    }

    [Theory(DisplayName = "§Token Revocation — an AS reports each resource in downstream; a failure is still 200")]
    [InlineData("unavailable", RevocationDownstreamError.RevocationUnavailable)]
    [InlineData("unsupported_iss", RevocationDownstreamError.RevocationUnsupported)]
    public async Task AccessServer_ReportsDownstreamOutcome_AndRetriesOnRepeat(string failure, RevocationDownstreamError expected)
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var person = await graph.IssuePersonTokenAsync(agent, FirstResource);
        var grant = await graph.GrantAsync(agent, FirstResource, true, personToken: person);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(grant, FirstResource));
        using var ps = graph.Signed(Person, AuthTokenBuilder.PersonDwk);

        graph.Failing[FirstResource] = failure;
        var reported = await Revoke(ps, Access, person);
        Assert.Equal(HttpStatusCode.OK, reported.StatusCode);
        Assert.Null(reported.Failure);
        var entry = Assert.Single(reported.Downstream);
        Assert.Equal(FirstResource, entry.Recipient);
        Assert.Equal(expected, entry.Error);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(grant, FirstResource));

        // Idempotent repeat re-attempts the failed downstream revocation.
        graph.Failing.Remove(FirstResource);
        var retried = await Revoke(ps, Access, person);
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        Assert.Null(Assert.Single(retried.Downstream).Error);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(grant, FirstResource));
        Assert.Contains(graph.Revocations, revocation => revocation.Token == new TokenKey(Access, (string)Decode(grant)["jti"]!));
    }

    [Fact(DisplayName = "§Token Revocation — a PS/AS revocation signature must cover content-type and content-digest")]
    public async Task IssuerRevocation_RequiresContentDigestCoverage()
    {
        await using var graph = await Graph.CreateAsync();
        using var ap = graph.SignedUncovered(FirstProvider, "aauth-agent.json");

        using var response = await ap.PostAsJsonAsync(Person + "/revoke", new { jti = "uncovered", exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("Signature-Error"));
    }

    [Fact]
    public async Task ResourceMiddleware_SameAuthJtiFromTwoIssuers_RemainsIsolated()
    {
        await using var graph = await Graph.CreateAsync();
        var first = await graph.AuthTokenAsync(Person, "same-auth-id");
        var second = await graph.AuthTokenAsync(Access, "same-auth-id");
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(first, FirstResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(second, FirstResource));
        using var person = graph.Signed(Person, "aauth-person.json");
        Assert.Equal(HttpStatusCode.OK, (await Revoke(person, FirstResource, first)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(first, FirstResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(second, FirstResource));
    }

    internal static JsonObject Decode(string token) => TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");

    internal static Task<RevocationResult> Revoke(HttpClient signer, string recipient, string token)
    {
        var payload = Decode(token);
        return new RevocationClient(signer).RevokeAsync(new Uri(recipient + "/revoke"), (string)payload["jti"]!,
            DateTimeOffset.FromUnixTimeSeconds((long)payload["exp"]!));
    }

    internal sealed class Graph : IAsyncDisposable
    {
        private readonly Dictionary<string, AAuthKey> _keys = new();
        private readonly Dictionary<string, WebApplication> _hosts = new();
        private readonly AAuthKey _agentKey = AAuthKey.Generate();
        private readonly Dictionary<string, AAuthKey> _agentKeys = new();
        public InMemoryPersonPendingStore Pending { get; } = new();
        public Asserter Consent { get; } = new(false);
        public InMemoryAgentPersonBindingStore Bindings { get; } = new();
        public InMemoryPersonResourceEnrollmentStore Enrollments { get; } = new();
        public List<(string Resource, TokenKey Token)> Revocations { get; } = [];
        public InMemoryJtiStore PersonInventory { get; } = new();
        public Dictionary<string, string> Failing { get; } = new();
        public int AccessTokenRequests { get; private set; }

        public static async Task<Graph> CreateAsync(bool consent = false)
        {
            var graph = new Graph();
            foreach (var issuer in new[] { Person, Access, FirstProvider, SecondProvider, FirstResource, SecondResource })
                graph._keys[issuer] = AAuthKey.Generate();
            await graph.StartResource(FirstResource);
            await graph.StartResource(SecondResource);
            var accessBuilder = graph.Builder();
            accessBuilder.Services.AddSingleton<IAccessPolicy>(new AllowPolicy());
            accessBuilder.Services.AddSingleton<IAccessPendingStore, InMemoryAccessPendingStore>();
            accessBuilder.Services.AddSingleton(new RevocationClient(graph.Signed(Access, AuthTokenBuilder.AccessDwk)));
            accessBuilder.Services.AddAAuthAccessServer(configure: o =>
            {
                o.EgressPolicy = TestEgress.Policy;
                o.Issuer = Access;
                o.SigningKeys = new AAuthSigningKeySet { ["key"] = graph._keys[Access] };
            });
            var access = accessBuilder.Build();
            access.MapAAuthAccessServer();
            await access.StartAsync();
            graph._hosts.Add(Access, access);
            var personBuilder = graph.Builder();
            personBuilder.Services.AddSingleton<IPersonPendingStore>(graph.Pending);
            personBuilder.Services.AddSingleton<IAgentPersonBindingStore>(graph.Bindings);
            personBuilder.Services.AddSingleton<IPersonResourceEnrollmentStore>(graph.Enrollments);
            graph.Consent.Required = consent;
            personBuilder.Services.AddSingleton<IIdentityClaimsAsserter>(graph.Consent);
            personBuilder.Services.AddSingleton(new RevocationClient(graph.Signed(Person, "aauth-person.json")));
            personBuilder.Services.AddSingleton(provider => new AccessServerClient(graph.Signed(Person, "aauth-person.json"),
                provider.GetRequiredService<MetadataClient>(), new AuthTokenResponseValidator(
                    provider.GetRequiredService<MetadataClient>(), provider.GetRequiredService<JwksClient>(), provider.GetRequiredService<TokenVerifier>())));
            personBuilder.Services.AddAAuthPersonServer(configure: o =>
                {
                    o.EgressPolicy = TestEgress.Policy;
                    o.Issuer = Person;
                    o.ConfigureRevocation = revocation => revocation.DeferAfter = TimeSpan.FromMilliseconds(200);
                    o.SigningKeys = new AAuthSigningKeySet { ["key"] = graph._keys[Person] };
                })
                .UseTokenInventory(graph.PersonInventory)
                .WithGovernance();
            var person = personBuilder.Build();
            person.MapAAuthPersonServer();
            person.MapAAuthGovernance(options => options.PersonServer = Person);
            await person.StartAsync();
            graph._hosts.Add(Person, person);
            return graph;
        }

        private WebApplicationBuilder Builder()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton(new AAuthVerifier());
            builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = TestEgress.Policy });
            builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(new Router(this))));
            builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(new Router(this))));
            builder.Services.AddSingleton<UpstreamTokenValidator>();
            return builder;
        }

        private async Task StartResource(string issuer)
        {
            var builder = Builder();
            var inventory = new InMemoryJtiStore();
            var app = builder.Build();
            app.Use(async (context, next) =>
            {
                context.Items[AAuthVerificationMiddleware.TokenStoreItemKey] = inventory;
                await next();
            });
            app.UseAAuthVerification(options =>
            {
                options.EgressPolicy = TestEgress.Policy;
                options.ResourceIdentifier = issuer;
                options.AcceptedSchemes = ["jwt", "jwks_uri"];
                options.ExpectedAuthTokenDwk = null;
                options.Trust.Policy = new MixedGraphTrustPolicy();
            });
            app.MapGet("/use", () => Results.Ok());
            app.Use(async (context, next) =>
            {
                if (context.Request.Path == "/revoke")
                {
                    if (Failing.GetValueOrDefault(issuer) == "slow") await Task.Delay(TimeSpan.FromSeconds(1));
                    if (Failing.GetValueOrDefault(issuer) == "unavailable")
                    {
                        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                        return;
                    }
                    context.Request.EnableBuffering();
                    var body = await context.Request.ReadFromJsonAsync<JsonObject>();
                    context.Request.Body.Position = 0;
                    var caller = context.Features.Get<AAuthVerificationResult>()?.Issuer;
                    if (caller is not null) Revocations.Add((issuer, new TokenKey(caller, (string)body!["jti"]!)));
                }
                await next();
            });
            // Each resource keeps its own inventory; a DI IJtiStore would also turn on replay detection.
            app.MapRevocationEndpointCore(inventory, options => options.IsAcceptedIssuer = caller =>
                caller == Person || caller == Access && Failing.GetValueOrDefault(issuer) != "unsupported_iss", "/revoke");
            await app.StartAsync();
            _hosts.Add(issuer, app);
        }

        private sealed class MixedGraphTrustPolicy : IAAuthTrustPolicy
        {
            public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
                => ValueTask.FromResult(context.Party switch
                {
                    AAuthTrustedParty.AuthTokenIssuer => context.TokenDwk switch
                    {
                        AuthTokenBuilder.AccessDwk => context.Issuer == Access,
                        AuthTokenBuilder.PersonDwk => context.Issuer == Person,
                        _ => false,
                    },
                    AAuthTrustedParty.PersonServer => true,
                    AAuthTrustedParty.AgentProvider => true,
                    AAuthTrustedParty.AccessServer => true,
                    _ => false,
                });
        }

        public async Task<string> AgentTokenAsync(string issuer, string tokenId, bool distinctKey = false)
        {
            var key = distinctKey ? AAuthKey.Generate() : _agentKey;
            _agentKeys[key.ComputeJwkThumbprint()] = key;
            return await new AgentTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = issuer, Subject = "aauth:demo@" + new Uri(issuer).Host, Key = _keys[issuer], KeyId = "key",
                ConfirmationKey = key, TokenId = tokenId, PersonServer = Person,
            }.BuildAsync();
        }

        public ValueTask<string> AuthTokenAsync(string issuer, string tokenId) => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = issuer, Audience = FirstResource, PersonServer = Person,
            AgentConfirmationKey = _agentKey, Key = _keys[issuer], KeyId = "key", Subject = "person",
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1), TokenId = tokenId,
            Dwk = issuer == Access ? AuthTokenBuilder.AccessDwk : AuthTokenBuilder.PersonDwk,
        }.BuildAsync();

        // The person token this PS issued the agent for the resource (the presented token).
        public async ValueTask<string> PersonTokenAsync(string agentToken, string resource)
        {
            var token = await new PersonTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = Person, Audience = resource, Subject = "person",
                ConfirmationKey = AgentKey(agentToken), AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                Key = _keys[Person], KeyId = "key",
            }.BuildAsync();
            await Enrollments.RecordAsync(new PersonResourceEnrollment(
                Person, new AAuthPersonKey("person"), resource, "person", "test", DateTimeOffset.UtcNow));
            return token;
        }

        public HttpClient Signed(string issuer, string dwk) => new InProcessHttpClient(new AAuthSigningHandler(_keys[issuer],
            new JwksUriSignatureKeyProvider(issuer, dwk, "key")) { InnerHandler = new Router(this) });

        // Signs without covering content-type/content-digest.
        public HttpClient SignedUncovered(string issuer, string dwk) => new InProcessHttpClient(new UncoveredBodySigner(
            new AAuthSigningHandler(_keys[issuer], new JwksUriSignatureKeyProvider(issuer, dwk, "key"))) { InnerHandler = new Router(this) });

        private AAuthKey AgentKey(string token)
        {
            var thumbprint = KeyFactory.FromPublicJwk((JsonObject)Decode(token)["cnf"]!["jwk"]!).ComputeJwkThumbprint();
            return _agentKeys.GetValueOrDefault(thumbprint, _agentKey);
        }

        public HttpClient AgentClient(string token) => new InProcessHttpClient(new AAuthSigningHandler(AgentKey(token),
            new JwtSignatureKeyProvider(() => token)) { InnerHandler = new Router(this) });

        public async Task<HttpResponseMessage> RequestAsync(string agentToken, string resource, bool federated, string? upstream = null,
            string? personToken = null)
        {
            personToken ??= await PersonTokenAsync(agentToken, resource);
            var person = Decode(personToken);
            var request = await new ResourceTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = resource, Audience = federated ? Access : Person,
                PersonServer = Person, Subject = (string)person["sub"]!, PresentedJti = (string)person["jti"]!,
                MissionS256 = (string?)person["mission_s256"],
                AgentJkt = AgentKey(agentToken).ComputeJwkThumbprint(), Key = _keys[resource], KeyId = "key",
            }.BuildAsync();
            using var client = AgentClient(agentToken);
            return await client.PostAsJsonAsync(Person + "/token", new { resource_token = request, presented_token = personToken, upstream_token = upstream });
        }

        public async Task<string> GrantAsync(string agentToken, string resource, bool federated, string? upstream = null,
            string? personToken = null)
        {
            using var response = await RequestAsync(agentToken, resource, federated, upstream, personToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!;
        }

        // A person token the PS issues and records against the agent token (§Person Token Endpoint).
        public async Task<string> IssuePersonTokenAsync(string agentToken, string resource)
        {
            using var client = AgentClient(agentToken);
            using var response = await client.PostAsJsonAsync(Person + "/person", new { resource });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["person_token"]!;
        }

        public async Task<HttpStatusCode> UseAsync(string token, string resource)
        {
            using var client = AgentClient(token);
            using var response = await client.GetAsync(resource + "/use");
            return response.StatusCode;
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var host in _hosts.Values) await host.DisposeAsync();
        }

        public IServiceProvider PersonServices => _hosts[Person].Services;

        public IAAuthRevocationService PersonRevocation
            => PersonServices.GetRequiredKeyedService<IAAuthRevocationService>(AAuthPersonServerBuilder.DefaultName);

        // A person token issued from an upstream token (#call-chaining).
        public async Task<string> IssueChainedPersonTokenAsync(string agentToken, string resource, string upstream)
        {
            using var client = AgentClient(agentToken);
            using var response = await client.PostAsJsonAsync(Person + "/person", new { resource, upstream_token = upstream });
            Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
            return (string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["person_token"]!;
        }

        private sealed class Router(Graph graph) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var issuer = request.RequestUri!.GetLeftPart(UriPartial.Authority);
                if (!graph._keys.TryGetValue(issuer, out var key)) return new(HttpStatusCode.NotFound);
                if (request.RequestUri.AbsolutePath.StartsWith("/.well-known/", StringComparison.Ordinal))
                {
                    var jwk = key.ToPublicJwk();
                    jwk["kid"] = "key";
                    var document = request.RequestUri.AbsolutePath.EndsWith("/keys", StringComparison.Ordinal)
                        ? new JsonObject { ["keys"] = new JsonArray(jwk) }
                        : new JsonObject { ["issuer"] = issuer, ["jwks_uri"] = issuer + "/.well-known/keys",
                            ["auth_token_endpoint"] = issuer + "/token", ["revocation_endpoint"] = issuer + "/revoke" };
                    return new(HttpStatusCode.OK) { Content = JsonContent.Create(document) };
                }
                if (issuer == Access && request.RequestUri.AbsolutePath == "/token")
                    graph.AccessTokenRequests++;
                if (!graph._hosts.TryGetValue(issuer, out var host)) return new(HttpStatusCode.NotFound);
                using var transport = new HttpMessageInvoker(host.GetTestServer().CreateHandler());
                return await transport.SendAsync(request, cancellationToken);
            }
        }

        public sealed class Asserter(bool consent) : IIdentityClaimsAsserter
        {
            public bool Required { get; set; } = consent;
            public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken ct = default)
                => Task.FromResult(Required ? IdentityAssertion.NeedsConsent() : IdentityAssertion.Assert(new AAuthPersonKey("person"), "person"));
        }

        private sealed class AllowPolicy : IAccessPolicy
        {
            public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken ct = default)
                => Task.FromResult(AccessDecision.Allow());
        }
    }
}