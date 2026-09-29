using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

public class IssuanceBoundsTests
{
    [Fact]
    public async Task AccessPolicy_CannotProjectUnsetReservedClaim()
    {
        await using var fixture = await IssuerFixture.CreateAsync(true, false, injectClaim: true);
        using var client = fixture.Client(120);
        using var response = await client.PostAsJsonAsync("/token", fixture.Request(120));
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("policy_error", (string?)body!["error"]);
        Assert.Null(body["auth_token"]);
    }

    [Theory]
    [InlineData(false, false, 120, 0)]
    [InlineData(false, true, 120, 0)]
    [InlineData(true, false, 120, 0)]
    [InlineData(true, true, 120, 0)]
    [InlineData(false, false, 120, 300)]
    [InlineData(false, true, 120, 300)]
    [InlineData(true, false, 120, 300)]
    [InlineData(true, true, 120, 300)]
    [InlineData(false, false, 300, 120)]
    [InlineData(false, true, 300, 120)]
    [InlineData(true, false, 300, 120)]
    [InlineData(true, true, 300, 120)]
    public async Task DirectAndDeferred_UseOriginalAgentAndParentBounds(bool access, bool deferred, int parentSeconds, int childSeconds)
    {
        await using var fixture = await IssuerFixture.CreateAsync(access, deferred);
        var started = fixture.Clock.Now;
        using var client = fixture.Client(parentSeconds);
        using var initial = await client.PostAsJsonAsync("/token", fixture.Request(parentSeconds, childSeconds));
        HttpResponseMessage response = initial;
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            fixture.Approve(initial);
            fixture.Clock.Now = started.AddSeconds(30);
            response = await client.GetAsync(initial.Headers.Location);
        }
        using (response)
        {
            var payload = await fixture.AssertTokenAsync(response, started.AddSeconds(120));
            Assert.Null(payload["agent"]);
            Assert.Null(payload["act"]);
            var boundKey = AAuthKey.FromJwk((JsonObject)payload["cnf"]!["jwk"]!);
            Assert.Equal((childSeconds > 0 ? fixture.ChildKey : fixture.ParentKey).ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());
        }
    }

    [Theory]
    [InlineData(false, 120, 0)]
    [InlineData(true, 120, 0)]
    [InlineData(false, 120, 300)]
    [InlineData(true, 120, 300)]
    [InlineData(false, 300, 120)]
    [InlineData(true, 300, 120)]
    public async Task Deferred_RejectsOriginalExpiryDespiteFreshPollCarrier(bool access, int parentSeconds, int childSeconds)
    {
        await using var fixture = await IssuerFixture.CreateAsync(access, true);
        using var client = fixture.Client(parentSeconds);
        using var pending = await client.PostAsJsonAsync("/token", fixture.Request(parentSeconds, childSeconds));
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        fixture.Approve(pending);
        fixture.Clock.Now = fixture.Clock.Now.AddSeconds(120);
        using var refreshed = fixture.Client(3600);
        using var response = await refreshed.GetAsync(pending.Headers.Location);
        await AssertExpiredAsync(response);
    }

    [Theory]
    [InlineData(false, 0, 0)]
    [InlineData(true, 0, 0)]
    [InlineData(false, -1, 0)]
    [InlineData(true, -1, 0)]
    [InlineData(false, 120, -1)]
    [InlineData(true, 120, -1)]
    public async Task Direct_RejectsExpiredParentOrChild(bool access, int parentSeconds, int childSeconds)
    {
        await using var fixture = await IssuerFixture.CreateAsync(access, false);
        using var client = fixture.Client(parentSeconds);
        using var response = await client.PostAsJsonAsync("/token", fixture.Request(parentSeconds, childSeconds));
        Assert.False(response.IsSuccessStatusCode);
        // A rejection may come from the signature layer (401 with no body) or the token endpoint.
        Assert.DoesNotContain("auth_token", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task UpstreamExpiry_IsPreservedThroughDeferredIssuance(bool access, bool deferred)
    {
        await using var fixture = await IssuerFixture.CreateAsync(access, deferred);
        var ceiling = fixture.Clock.Now.AddSeconds(60);
        using var client = fixture.Client(300);
        using var initial = await client.PostAsJsonAsync("/token", fixture.Request(300, 120, upstream: true));
        HttpResponseMessage response = initial;
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            fixture.Approve(initial);
            fixture.Clock.Now = fixture.Clock.Now.AddSeconds(20);
            response = await client.GetAsync(initial.Headers.Location);
        }
        using (response)
        {
            var payload = await fixture.AssertTokenAsync(response, ceiling);
            // The downstream token names the resource token's person, never the upstream sub.
            Assert.Equal("user", (string?)payload["sub"]);
            Assert.Null(payload["act"]);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClaimsPush_UsesOriginalExpiryAndTypedIdentityClaims(bool expired)
    {
        await using var fixture = await IssuerFixture.CreateAsync(true, true, claims: true);
        var ceiling = fixture.Clock.Now.AddSeconds(120);
        using var client = fixture.Client(120);
        using var pending = await client.PostAsJsonAsync("/token", fixture.Request(120));
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        fixture.Clock.Now = fixture.Clock.Now.AddSeconds(expired ? 120 : 30);
        using var response = await client.PostAsJsonAsync(pending.Headers.Location, new JsonObject
        {
            ["email"] = "user@example.test", ["tenant"] = "org",
            ["roles"] = new JsonArray("reader"), ["groups"] = new JsonArray("team"),
        });
        if (expired) { await AssertExpiredAsync(response); return; }
        var payload = await fixture.AssertTokenAsync(response, ceiling);
        Assert.Equal("org", (string?)payload["tenant"]);
        Assert.Equal("reader", (string?)payload["roles"]?[0]);
        Assert.Equal("team", (string?)payload["groups"]?[0]);
        Assert.Equal("user@example.test", (string?)payload["email"]);
    }

    private static async Task AssertExpiredAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.RequestTimeout, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("expired", (string?)body!["error"]);
        Assert.Null(body["auth_token"]);
    }

    private sealed class IssuerFixture : IAsyncDisposable
    {
        public const string ParentId = "aauth:parent@ap.test";
        public const string ChildId = "aauth:parent+child@ap.test";
        private const string Ps = "https://ps.test";
        private const string As = "https://as.test";
        private const string Ap = "https://ap.test";
        private const string Resource = "https://resource.test";
        public required WebApplication App { get; init; }
        public required MutableClock Clock { get; init; }
        public required bool Access { get; init; }
        public required AAuthKey IssuerKey { get; init; }
        public required AAuthKey PsKey { get; init; }
        public required AAuthKey ApKey { get; init; }
        public required AAuthKey ResourceKey { get; init; }
        public AAuthKey ParentKey { get; } = AAuthKey.Generate();
        public AAuthKey ChildKey { get; } = AAuthKey.Generate();

        public static async Task<IssuerFixture> CreateAsync(bool access, bool deferred, bool claims = false, bool injectClaim = false)
        {
            var clock = new MutableClock();
            var issuerKey = AAuthKey.Generate();
            var psKey = access ? AAuthKey.Generate() : issuerKey;
            var apKey = AAuthKey.Generate();
            var resourceKey = AAuthKey.Generate();
            var discovery = new DiscoveryHandler(new Dictionary<string, IAAuthKey>
            {
                [Ps] = psKey, [As] = issuerKey, [Ap] = apKey, [Resource] = resourceKey,
            });
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton(new AAuthVerifier());
            builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = TestEgress.Policy, TimeProvider = clock });
            builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
            builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
            builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
            builder.Services.AddSingleton<IAccessPendingStore, InMemoryAccessPendingStore>();
            builder.Services.AddSingleton<IIdentityClaimsAsserter>(new Asserter(deferred));
            builder.Services.AddSingleton<IAccessPolicy>(new Policy(deferred, claims, injectClaim));
            builder.Services.AddSingleton(provider => new UpstreamTokenValidator(
                provider.GetRequiredService<MetadataClient>(), provider.GetRequiredService<JwksClient>(),
                provider.GetRequiredService<TokenVerifier>()));
            var app = builder.Build();
            if (access)
                app.MapAAuthAccessServer(new AAuthAccessServerOptions
                {
                    EgressPolicy = TestEgress.Policy,
                    Issuer = As, SigningKeys = new Dictionary<string, IAAuthKey> { ["key"] = issuerKey },
                    TrustedPersonServers = [Ps], TimeProvider = clock,
                });
            else
                app.MapAAuthPersonServer(new AAuthPersonServerOptions
                {
                    EgressPolicy = TestEgress.Policy,
                    Issuer = Ps, SigningKeys = new Dictionary<string, IAAuthKey> { ["key"] = issuerKey },
                    TrustedAccessServers = [], TimeProvider = clock,
                });
            await app.StartAsync();
            return new IssuerFixture { App = app, Access = access, Clock = clock, IssuerKey = issuerKey,
                PsKey = psKey, ApKey = apKey, ResourceKey = resourceKey };
        }

        private string AgentToken(int seconds, bool child = false) => new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = Ap, Subject = child ? ChildId : ParentId, Key = ApKey, KeyId = "key",
            ConfirmationKey = child ? ChildKey : ParentKey, ParentAgent = child ? ParentId : null,
            PersonServer = Ps, IssuedAt = Clock.Now.AddSeconds(seconds - 3600), Lifetime = TimeSpan.FromHours(1),
        }.Build();

        public HttpClient Client(int parentSeconds)
        {
            var client = Access
                ? new AAuthClientBuilder(PsKey).UseJwksUri(Ps, AAuthConstants.DwkFiles.Person, "key")
                    .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(App.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly).Build()
                : new InProcessHttpClient(new AAuthSigningHandler(ParentKey, () => AgentToken(parentSeconds))
                    { InnerHandler = App.GetTestServer().CreateHandler() });
            client.BaseAddress = new Uri(Access ? As : Ps);
            return client;
        }

        public JsonObject Request(int parentSeconds, int childSeconds = 0, bool upstream = false)
        {
            var mission = Access && upstream ? "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" : null;
            var agentKey = childSeconds != 0 ? ChildKey : ParentKey;
            // The presented person token outlives every ceiling these tests assert.
            var personToken = new PersonTokenBuilder
            {
                EgressPolicy = TestEgress.Policy,
                Issuer = Ps, Audience = Resource, Subject = "user", ConfirmationKey = agentKey,
                AgentTokenExpiresAt = Clock.Now.AddHours(1), TimeProvider = Clock, MissionS256 = mission,
                Key = PsKey, KeyId = "key",
            }.Build();
            var body = new JsonObject
            {
                ["agent_token"] = AgentToken(parentSeconds),
                ["resource_token"] = new ResourceTokenBuilder
                {
                    ScopeDescriptions = TestScopeDefinitions.Resource,
                    EgressPolicy = TestEgress.Policy,
                    Issuer = Resource, Audience = Access ? As : Ps, PersonServer = Ps, Subject = "user",
                    PresentedJti = (string)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(personToken.Split('.')[1]))!["jti"]!,
                    AgentJkt = agentKey.ComputeJwkThumbprint(),
                    Key = ResourceKey, KeyId = "key", Scope = "read",
                    MissionS256 = mission, IssuedAt = Clock.Now,
                }.Build(),
                ["presented_token"] = personToken,
            };
            if (childSeconds != 0) body["subagent_token"] = AgentToken(childSeconds, child: true);
            if (upstream) body["upstream_token"] = new AuthTokenBuilder
            {
                EgressPolicy = TestEgress.Policy,
                Issuer = Access ? As : Ps, Audience = Ap, PersonServer = Ps, Subject = "upstream-person",
                AgentConfirmationKey = ParentKey, Key = IssuerKey, KeyId = "key", Scope = "read",
                AgentTokenExpiresAt = Clock.Now.AddSeconds(60), TimeProvider = Clock,
                Dwk = Access ? AuthTokenBuilder.AccessDwk : AuthTokenBuilder.PersonDwk,
                MissionS256 = mission,
            }.Build();
            return body;
        }

        public void Approve(HttpResponseMessage pending)
        {
            var id = pending.Headers.Location!.OriginalString.Split('/')[^1];
            if (Access) App.Services.GetRequiredService<IAccessPendingStore>().MarkAllowed(id);
            else App.Services.GetRequiredService<IPersonPendingStore>().MarkAllowed(id, "user");
        }

        public async Task<JsonObject> AssertTokenAsync(HttpResponseMessage response, DateTimeOffset expectedExpiry)
        {
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
            var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
            var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(((string)body["auth_token"]!).Split('.')[1]))!;
            Assert.Equal(expectedExpiry.ToUnixTimeSeconds(), (long)payload["exp"]!);
            Assert.Equal(expectedExpiry.ToUnixTimeSeconds() - Clock.Now.ToUnixTimeSeconds(), (long)body["expires_in"]!);
            return payload;
        }

        public ValueTask DisposeAsync() => App.DisposeAsync();
    }

    private sealed class MutableClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Asserter(bool deferred) : IIdentityClaimsAsserter
    {
        public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(deferred ? IdentityAssertion.NeedsConsent() : IdentityAssertion.Assert("user"));
    }

    private sealed class Policy(bool deferred, bool claims, bool injectClaim) : IAccessPolicy
    {
        public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(injectClaim ? AccessDecision.Allow(additionalClaims: new Dictionary<string, JsonNode?> { ["act"] = "injected" })
                : request.Claims is not null || !deferred ? AccessDecision.Allow()
                : claims ? AccessDecision.NeedsClaims(["email", "tenant", "roles", "groups"]) : AccessDecision.NeedsInteraction());
    }

    private sealed class DiscoveryHandler(Dictionary<string, IAAuthKey> keys) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var issuer = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            var jwk = keys[issuer].ToPublicJwk();
            jwk["kid"] = "key";
            var body = request.RequestUri.AbsolutePath.EndsWith("/jwks.json", StringComparison.Ordinal)
                ? new JsonObject { ["keys"] = new JsonArray(jwk) }
                : new JsonObject { ["issuer"] = issuer, ["jwks_uri"] = $"{issuer}/.well-known/jwks.json" };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(body) });
        }
    }
}