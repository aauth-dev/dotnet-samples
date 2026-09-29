using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
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

namespace AAuth.Conformance.Missions;

/// <summary>
/// §Mission Approval <c>person_tokens</c>: a PS hosting both <c>MapAAuthPersonServer</c>
/// and <c>MapAAuthGovernance</c> issues a mission-bound person token for each approved
/// resource it asserts, bound to the proposing agent's key and tracked against its agent token.
/// </summary>
public class MissionPersonTokenIssuanceTests
{
    private const string PsIssuer = "https://ps.test";
    private const string AgentId = "aauth:demo@ap.example";
    private const string ApKid = "ap-1";
    private const string PsKid = "ps-1";
    private const string Whoami = "https://whoami.test";
    private const string Calendar = "https://calendar.test";
    private const string Consent = "https://consent.test";
    private const string Denied = "https://denied.test";

    private static readonly AAuthKey ApKey = AAuthKey.Generate();
    private static readonly AAuthKey PsKey = AAuthKey.Generate();

    private sealed class PublicDns : IAAuthDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    private static async Task<IHost> BuildHostAsync(IMissionApprover approver, bool deferred = false)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { MaxAge = TimeSpan.FromSeconds(300) });
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = TestEgress.Policy });
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(new StubAgentProviderHandler())));
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(new StubAgentProviderHandler())));
        builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore());
        builder.Services.AddAAuthGovernance();
        if (deferred) builder.Services.AddAAuthDeferredConsent();
        builder.Services.AddSingleton(approver);
        builder.Services.AddSingleton(sp => new UpstreamTokenValidator(
            sp.GetRequiredService<MetadataClient>(), sp.GetRequiredService<JwksClient>()));
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(new PerResourceAsserter());
        builder.Services.AddRouting();

        var app = builder.Build();
        app.MapAAuthPersonServer(new AAuthPersonServerOptions
        {
            EgressPolicy = new AAuthEgressPolicy(dnsResolver: new PublicDns()),
            Issuer = PsIssuer,
            SigningKeys = new AAuthSigningKeySet { [PsKid] = PsKey },
            Trust = { AccessServers = { Allowed = new HashSet<string>() } },
        });
        app.MapAAuthGovernance(options => options.PersonServer = PsIssuer);
        await app.StartAsync();
        return app;
    }

    private static ValueTask<string> AgentTokenAsync(AAuthKey agentKey) => new AgentTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = "https://ap.example",
        Subject = AgentId,
        KeyId = ApKid,
        Key = ApKey,
        ConfirmationKey = agentKey,
        PersonServer = PsIssuer,
    }.BuildAsync();

    private static HttpClient SignedAgentClient(IHost host, AAuthKey agentKey, string agentToken)
        => new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = host.GetTestServer().CreateHandler(),
        }) { BaseAddress = new Uri(PsIssuer) };

    private static JsonObject Proposal(params string[] resources)
    {
        var body = new JsonObject { ["description"] = "# Plan the offsite" };
        if (resources.Length > 0) body["resources"] = new JsonArray(resources.Select(r => (JsonNode?)r).ToArray());
        return body;
    }

    private static JsonObject Decode(string jwt, int segment = 1)
        => TokenVerifier.DecodeJsonSegment(jwt.Split('.')[segment], "payload");

    private static void AssertMissionPersonToken(string token, string resource, AAuthKey agentKey, string agentToken,
        string s256, DateTimeOffset? missionExpiresAt)
    {
        Assert.Equal(PersonTokenBuilder.TokenType, (string?)Decode(token, 0)["typ"]);
        var payload = Decode(token);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(resource, (string?)payload["aud"]);
        Assert.Equal("user-42", (string?)payload["sub"]);
        Assert.Equal(s256, (string?)payload["mission_s256"]);
        Assert.Null(payload["scope"]);
        Assert.Null(payload["account"]);
        Assert.Equal(agentKey.ComputeJwkThumbprint(),
            AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!).ComputeJwkThumbprint());
        var exp = (long)payload["exp"]!;
        Assert.True(exp - (long)payload["iat"]! <= 3600);
        Assert.True(exp <= (long)Decode(agentToken)["exp"]!);
        if (missionExpiresAt is { } ceiling) Assert.True(exp <= ceiling.ToUnixTimeSeconds());
    }

    [Fact(DisplayName = "§Mission Approval — person_tokens carries a mission-bound person token for each asserted resource")]
    public async Task Approval_IssuesPersonTokenPerAssertedResource()
    {
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(20);
        using var host = await BuildHostAsync(new StubApprover(MissionApprovalDecision.Approve([]) with { ExpiresAt = expiresAt }));
        var agentKey = AAuthKey.Generate();
        var agentToken = await AgentTokenAsync(agentKey);
        using var http = SignedAgentClient(host, agentKey, agentToken);

        using var response = await http.PostAsJsonAsync("/mission", Proposal(Whoami, Calendar, Consent, Denied));

        Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        var mission = Mission.FromApprovalResponse(await response.Content.ReadAsByteArrayAsync(), PsIssuer);
        Assert.Equal(new[] { Whoami, Calendar, Consent, Denied }, mission.ApprovedResources);
        // A resource the asserter defers or denies is omitted, not failed.
        Assert.Equal(new[] { Calendar, Whoami }, mission.PersonTokens.Keys.Order(StringComparer.Ordinal));
        foreach (var (resource, token) in mission.PersonTokens)
            AssertMissionPersonToken(token, resource, agentKey, agentToken, mission.S256, expiresAt);
    }

    [Fact(DisplayName = "§Mission Approval — a proposal naming no resources has no person_tokens member")]
    public async Task Approval_WithoutResources_OmitsPersonTokens()
    {
        using var host = await BuildHostAsync(new StubApprover(MissionApprovalDecision.Approve([])));
        var agentKey = AAuthKey.Generate();
        using var http = SignedAgentClient(host, agentKey, await AgentTokenAsync(agentKey));

        using var response = await http.PostAsJsonAsync("/mission", Proposal());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.False(body.ContainsKey("person_tokens"));
        Assert.Empty(Mission.FromApprovalResponse(System.Text.Encoding.UTF8.GetBytes(body.ToJsonString()), PsIssuer).PersonTokens);
    }

    [Theory(DisplayName = "§Mission Approval — a partial resource approval limits approved_resources and person_tokens")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PartialResourceApproval_LimitsApprovedResourcesAndPersonTokens(bool deferred)
    {
        var decision = (deferred ? MissionApprovalDecision.Defer() : MissionApprovalDecision.Approve([]))
            with { ApprovedResources = [Calendar, "https://not-proposed.example"] };
        using var host = await BuildHostAsync(new StubApprover(decision), deferred);
        var agentKey = AAuthKey.Generate();
        using var http = SignedAgentClient(host, agentKey, await AgentTokenAsync(agentKey));

        var response = await http.PostAsJsonAsync("/mission", Proposal(Whoami, Calendar));
        if (deferred)
        {
            var location = response.Headers.Location!.ToString();
            await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(location.Split('/').Last(), true);
            response.Dispose();
            response = await http.GetAsync(location);
        }

        using (response)
        {
            Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
            var mission = Mission.FromApprovalResponse(await response.Content.ReadAsByteArrayAsync(), PsIssuer);
            Assert.Equal(new[] { Calendar }, mission.ApprovedResources);
            Assert.Equal(new[] { Calendar }, mission.PersonTokens.Keys);
        }
    }

    [Fact(DisplayName = "§Mission Approval — a deferred approval returns person_tokens once the person approves")]
    public async Task DeferredApproval_ReturnsPersonTokens()
    {
        using var host = await BuildHostAsync(new StubApprover(MissionApprovalDecision.Defer()), deferred: true);
        var agentKey = AAuthKey.Generate();
        var agentToken = await AgentTokenAsync(agentKey);
        using var http = SignedAgentClient(host, agentKey, agentToken);

        using var parked = await http.PostAsJsonAsync("/mission", Proposal(Whoami, Denied));
        Assert.Equal(HttpStatusCode.Accepted, parked.StatusCode);
        var location = parked.Headers.Location!.ToString();
        await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(location.Split('/').Last(), true);
        using var approved = await http.GetAsync(location);

        Assert.True(approved.StatusCode == HttpStatusCode.OK, await approved.Content.ReadAsStringAsync());
        var mission = Mission.FromApprovalResponse(await approved.Content.ReadAsByteArrayAsync(), PsIssuer);
        var (resource, token) = Assert.Single(mission.PersonTokens);
        Assert.Equal(Whoami, resource);
        AssertMissionPersonToken(token, Whoami, agentKey, agentToken, mission.S256, missionExpiresAt: null);
    }

    [Fact(DisplayName = "§Token Revocation — a mission-issued person token is recorded as a grant of the agent token")]
    public async Task ApprovalPersonToken_IsGrantOfAgentToken()
    {
        using var host = await BuildHostAsync(new StubApprover(MissionApprovalDecision.Approve([])));
        var agentKey = AAuthKey.Generate();
        var agentToken = await AgentTokenAsync(agentKey);
        using var http = SignedAgentClient(host, agentKey, agentToken);

        using var response = await http.PostAsJsonAsync("/mission", Proposal(Whoami));
        var mission = Mission.FromApprovalResponse(await response.Content.ReadAsByteArrayAsync(), PsIssuer);

        var inventory = host.Services.GetRequiredService<IJtiStore>();
        var agentPayload = Decode(agentToken);
        var agentKeyInInventory = new TokenKey((string)agentPayload["iss"]!, (string)agentPayload["jti"]!);
        var personPayload = Decode(mission.PersonTokens[Whoami]);
        var grant = Assert.Single(await inventory.GetGrantsAsync(agentKeyInInventory));
        Assert.Equal(new TokenKey(PsIssuer, (string)personPayload["jti"]!), grant.Token);
        Assert.Equal(Whoami, grant.Resource);

        await inventory.RevokeAsync(agentKeyInInventory, DateTimeOffset.FromUnixTimeSeconds((long)agentPayload["exp"]!));
        Assert.True(await inventory.IsRevokedAsync(grant.Token));
    }

    [Fact(DisplayName = "§Mission Approval — a deferred approval polled with a revoked agent token yields no person_tokens")]
    public async Task RevokedAgentToken_GetsNoPersonTokens()
    {
        using var host = await BuildHostAsync(new StubApprover(MissionApprovalDecision.Defer()), deferred: true);
        var agentKey = AAuthKey.Generate();
        var agentToken = await AgentTokenAsync(agentKey);
        using var http = SignedAgentClient(host, agentKey, agentToken);
        using var parked = await http.PostAsJsonAsync("/mission", Proposal(Whoami));
        var location = parked.Headers.Location!.ToString();
        await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(location.Split('/').Last(), true);
        var agentPayload = Decode(agentToken);
        await host.Services.GetRequiredService<IJtiStore>().RevokeAsync(
            new TokenKey((string)agentPayload["iss"]!, (string)agentPayload["jti"]!),
            DateTimeOffset.FromUnixTimeSeconds((long)agentPayload["exp"]!));

        using var poll = await http.GetAsync(location);

        // The verification middleware refuses the revoked carrier before the poll resolves.
        Assert.Equal(HttpStatusCode.Unauthorized, poll.StatusCode);
    }

    private sealed class StubApprover(MissionApprovalDecision decision) : IMissionApprover
    {
        public Task<MissionApprovalDecision> ApproveAsync(MissionApprovalContext context, CancellationToken ct = default)
            => Task.FromResult(decision);
    }

    private sealed class PerResourceAsserter : IIdentityClaimsAsserter
    {
        public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(request.ResourceUrl switch
            {
                Consent => IdentityAssertion.NeedsConsent(),
                Denied => IdentityAssertion.Deny("not for this resource"),
                _ => IdentityAssertion.Assert("user-42"),
            });
    }

    // Serves the agent provider's metadata + JWKS so the PS verifies agent tokens in-process.
    private sealed class StubAgentProviderHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authority = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            JsonObject document;
            if (request.RequestUri.AbsolutePath.StartsWith("/.well-known/aauth-", StringComparison.Ordinal))
            {
                document = new JsonObject { ["issuer"] = authority, ["jwks_uri"] = $"{authority}/.well-known/jwks.json" };
            }
            else
            {
                var jwk = ApKey.ToPublicJwk();
                jwk["kid"] = ApKid;
                jwk["use"] = "sig";
                jwk["alg"] = AAuthKey.Ed25519Algorithm;
                document = new JsonObject { ["keys"] = new JsonArray(jwk) };
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(document.ToJsonString(), System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
