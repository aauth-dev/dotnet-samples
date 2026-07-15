using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Agent;
using AAuth.Events.DependencyInjection;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tokens;
using AAuth.Events.Tests.TestSupport;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Events.Tests.Agent;

public sealed class EventTokenVerifierTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task VerifiesResourceEventAndUsesExactTokenHash(string algorithm)
    {
        IAAuthKey key = algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();
        var resolver = CreateResolver(key);
        var token = EventsTestData.Event(key, jti: "jti-1", eid: "eid-1").Token;
        var verifier = new EventTokenVerifier(
            resolver,
            "aauth:agent@ap.example",
            new DelegateEventContextLookup((string eid) =>
                eid == "eid-1" ? new object() : null));

        var result = await verifier.VerifyAsync(
            token,
            new UnauthenticatedEventPayload(
                Encoding.UTF8.GetBytes("""{"display":"hint"}"""),
                "application/json"));

        Assert.Equal(AgentEventVerificationStatus.Verified, result.Status);
        Assert.True(result.IsActionable);
        Assert.Equal(
            EventTokenVerifier.ComputeIdempotencyKey(token),
            result.IdempotencyKey);
        Assert.False(result.Event!.Payload!.IsAuthenticated);
        Assert.NotNull(result.Event.VerifiedToken);
    }

    [Fact]
    public async Task UnknownContextIsTypedAndNonActionable()
    {
        var key = AAuthKey.Generate();
        var resolver = CreateResolver(key);
        var token = EventsTestData.Event(key, eid: "not-local").Token;
        var verifier = new EventTokenVerifier(
            resolver,
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => null));

        var result = await verifier.VerifyAsync(token);

        Assert.Equal(AgentEventVerificationStatus.UnknownContext, result.Status);
        Assert.False(result.IsActionable);
        Assert.Null(result.Event);
    }

    [Fact]
    public async Task ExactReplayIsIgnoredButDistinctTokensWithSameEidAreAccepted()
    {
        var key = AAuthKey.Generate();
        var resolver = CreateResolver(key);
        var verifier = new EventTokenVerifier(
            resolver,
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));
        var first = EventsTestData.Event(key, jti: "one", eid: "same-eid").Token;
        var second = EventsTestData.Event(key, jti: "two", eid: "same-eid").Token;

        Assert.Equal(
            AgentEventVerificationStatus.Verified,
            (await verifier.VerifyAsync(first)).Status);
        Assert.Equal(
            AgentEventVerificationStatus.Duplicate,
            (await verifier.VerifyAsync(first)).Status);
        Assert.Equal(
            AgentEventVerificationStatus.Verified,
            (await verifier.VerifyAsync(second)).Status);
    }

    [Fact]
    public async Task PayloadSubstitutionCannotChangeTokenVerificationOrTrustLabel()
    {
        var key = AAuthKey.Generate();
        var token = EventsTestData.Event(key, jti: "payload-jti").Token;
        var first = new EventTokenVerifier(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));
        var second = new EventTokenVerifier(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));

        var original = await first.VerifyAsync(token, new UnauthenticatedEventPayload(
            Encoding.UTF8.GetBytes("""{"value":"original"}"""), "application/json"));
        var substituted = await second.VerifyAsync(token, new UnauthenticatedEventPayload(
            Encoding.UTF8.GetBytes("""{"value":"substituted"}"""), "application/json"));

        Assert.True(original.IsActionable);
        Assert.True(substituted.IsActionable);
        Assert.NotEqual(
            original.Event!.Payload!.GetUtf8Text(),
            substituted.Event!.Payload!.GetUtf8Text());
        Assert.False(substituted.Event.Payload.IsAuthenticated);
    }

    [Fact]
    public void DependencyInjectionResolvesVerifierWithConfiguredAudience()
    {
        const string expectedAudience = "aauth:agent@ap.example";
        var services = new ServiceCollection();
        services.AddAAuthEventsAgent(
            expectedAudience,
            new DelegateEventContextLookup(static (string _) => new object()));

        using var provider = services.BuildServiceProvider();
        var verifier = provider.GetRequiredService<EventTokenVerifier>();

        Assert.Equal(expectedAudience, verifier.ExpectedAudience);
        Assert.NotNull(provider.GetRequiredService<EventsJwtKeyResolver>());
        Assert.NotNull(provider.GetRequiredService<IEventContextLookup>());
        Assert.NotNull(provider.GetRequiredService<IEventDeduplicator>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("resource.example")]
    public void DependencyInjectionRejectsMissingOrInvalidAudience(string? expectedAudience)
    {
        var services = new ServiceCollection();

        var error = Assert.Throws<ArgumentException>(() =>
            services.AddAAuthEventsAgent(
                expectedAudience!,
                new DelegateEventContextLookup(static (string _) => new object())));

        Assert.Contains("ExpectedAudience", error.Message);
    }

    [Fact]
    public async Task WrongAudienceThrowsTypedVerificationFailure()
    {
        var key = AAuthKey.Generate();
        var token = new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:other-agent@ap.example",
            Eid = "event-1",
            KeyId = "resource-1",
            Key = key,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
        }.Build().Token;
        var verifier = NewVerifier(key);

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            verifier.VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.WrongAudience, error.Error.Code);
    }

    [Fact]
    public async Task ExpiredTokenThrowsTypedVerificationFailure()
    {
        var key = AAuthKey.Generate();
        var token = new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:agent@ap.example",
            Eid = "event-1",
            KeyId = "resource-1",
            Key = key,
            IssuedAt = EventsTestData.Now.AddMinutes(-10),
            Lifetime = TimeSpan.FromMinutes(5),
        }.Build().Token;
        var verifier = NewVerifier(key);

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            verifier.VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.ExpiredToken, error.Error.Code);
    }

    [Fact]
    public async Task ForgedTokenThrowsTypedSignatureFailure()
    {
        var trustedKey = AAuthKey.Generate();
        var forgedKey = AAuthKey.Generate();
        var token = EventsTestData.Event(forgedKey).Token;
        var verifier = NewVerifier(trustedKey);

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            verifier.VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, error.Error.Code);
    }

    private static EventTokenVerifier NewVerifier(IAAuthKey key) =>
        new(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));

    private static EventsJwtKeyResolver CreateResolver(IAAuthKey key)
    {
        var http = new HttpClient(new DiscoveryHandler(key));
        var tokenVerifier = new TokenVerifier
        {
            Clock = () => EventsTestData.Now,
            ClockSkew = TimeSpan.Zero,
        };
        return new EventsJwtKeyResolver(
            new MetadataClient(http, clock: () => EventsTestData.Now),
            new JwksClient(http, minRefreshInterval: TimeSpan.Zero,
                clock: () => EventsTestData.Now),
            new DefaultEventsUrlPolicy(),
            tokenVerifier);
    }

    private sealed class DiscoveryHandler : HttpMessageHandler
    {
        private readonly IAAuthKey _key;

        public DiscoveryHandler(IAAuthKey key) => _key = key;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var uri = request.RequestUri!.ToString();
            if (uri == "https://resource.example/.well-known/aauth-resource.json")
            {
                return Task.FromResult(Json(new JsonObject
                {
                    ["issuer"] = "https://resource.example",
                    ["jwks_uri"] = "https://resource.example/jwks",
                }));
            }

            if (uri == "https://resource.example/jwks")
            {
                var jwk = _key.ToPublicJwk();
                jwk["kid"] = "resource-1";
                jwk["alg"] = _key.Algorithm;
                return Task.FromResult(Json(new JsonObject
                {
                    ["keys"] = new JsonArray(jwk),
                }));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage Json(JsonObject document) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    document.ToJsonString(),
                    Encoding.UTF8,
                    AAuthEventsConstants.JsonMediaType),
            };
    }
}
