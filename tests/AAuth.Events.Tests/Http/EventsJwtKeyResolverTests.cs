using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests.Http;

public sealed class EventsJwtKeyResolverTests
{
    private const string ResourceIssuer = "https://resource.example";
    private const string ApIssuer = "https://ap.example";
    private const string Kid = "key-1";

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task EventResolutionUsesSameJwtAndHttpKey(string algorithm)
    {
        var key = CreateKey(algorithm);
        var handler = DiscoveryHandler.For(ResourceIssuer, AAuthEventsConstants.ResourceDwk, Kid, key);
        var resolver = CreateResolver(handler);
        var token = BuildEvent(key);

        var result = await resolver.ResolveEventAsync(
            token, "aauth:agent@ap.example");

        Assert.Equal(
            key.ComputeJwkThumbprint(),
            result.JwtIssuerKey.ComputeJwkThumbprint());
        Assert.Equal(
            result.JwtIssuerKey.ComputeJwkThumbprint(),
            result.HttpSignatureKey.ComputeJwkThumbprint());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task SubscribeResolutionRequiresExpectedAudienceBeforeDiscovery(string? audience)
    {
        var apKey = AAuthKey.Generate();
        var agentKey = EcdsaAAuthKey.Generate();
        var handler = DiscoveryHandler.For(ApIssuer, AAuthEventsConstants.AgentDwk, Kid, apKey);
        var resolver = CreateResolver(handler);
        var token = new SubscribeTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = Kid,
            Key = apKey,
            ConfirmationKey = agentKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = "eid-1",
        }.Build().Token;

        await Assert.ThrowsAsync<ArgumentException>(() =>
            resolver.ResolveSubscribeAsync(token, audience!));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            resolver.ResolveAsync(token, EventsTokenKind.Subscribe, audience));

        Assert.Equal(0, handler.MetadataRequestCount);
        Assert.Equal(0, handler.JwksRequestCount);
    }

    [Fact]
    public async Task WrongSubscribeAudienceIsRejectedBeforeDiscovery()
    {
        var apKey = AAuthKey.Generate();
        var agentKey = EcdsaAAuthKey.Generate();
        var handler = new CountingThrowingDiscoveryHandler();
        var resolver = CreateResolver(handler);
        var token = new SubscribeTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = Kid,
            Key = apKey,
            ConfirmationKey = agentKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = "eid-1",
        }.Build().Token;

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveSubscribeAsync(token, "https://other.example"));

        Assert.Equal(EventsVerificationErrorCode.WrongAudience, error.Error.Code);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task EventResolutionAllowsNullExpectedAudience()
    {
        var key = CreateKey("EdDSA");
        var handler = DiscoveryHandler.For(ResourceIssuer, AAuthEventsConstants.ResourceDwk, Kid, key);
        var resolver = CreateResolver(handler);
        var token = BuildEvent(key);

        var result = await resolver.ResolveEventAsync(token);

        Assert.Equal(key.ComputeJwkThumbprint(), result.JwtIssuerKey.ComputeJwkThumbprint());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task RegistrationVerifierRequiresExpectedAudienceBeforeDiscovery(string? audience)
    {
        var apKey = AAuthKey.Generate();
        var agentKey = EcdsaAAuthKey.Generate();
        var handler = DiscoveryHandler.For(ApIssuer, AAuthEventsConstants.AgentDwk, Kid, apKey);
        var resolver = CreateResolver(handler);
        var verifier = new SubscriptionRegistrationVerifier(
            resolver,
            new EventsHttpMessageVerifier
            {
                Clock = () => EventsTestData.Now,
                FutureSkew = TimeSpan.Zero,
            });
        using var request = JsonRequest();
        var token = new SubscribeTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = Kid,
            Key = apKey,
            ConfirmationKey = agentKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = "eid-1",
        }.Build().Token;
        new EventsRequestSigner(agentKey, () => token, () => EventsTestData.Now)
            .SignRegistration(request);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            verifier.VerifyAsync(request, audience!, wirePath: "/waitlist"));

        Assert.Equal(0, handler.MetadataRequestCount);
        Assert.Equal(0, handler.JwksRequestCount);
    }

    [Fact]
    public async Task SubscribeResolutionReturnsAgentConfirmationKey()
    {
        var apKey = AAuthKey.Generate();
        var agentKey = EcdsaAAuthKey.Generate();
        var handler = DiscoveryHandler.For(ApIssuer, AAuthEventsConstants.AgentDwk, Kid, apKey);
        var resolver = CreateResolver(handler);
        var token = new SubscribeTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = Kid,
            Key = apKey,
            ConfirmationKey = agentKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = "eid-1",
        }.Build().Token;

        var result = await resolver.ResolveSubscribeAsync(
            token, "https://resource.example");

        Assert.Equal(apKey.ComputeJwkThumbprint(), result.JwtIssuerKey.ComputeJwkThumbprint());
        Assert.Equal(agentKey.ComputeJwkThumbprint(), result.HttpSignatureKey.ComputeJwkThumbprint());
    }

    [Fact]
    public async Task RegistrationFailsWhenHttpKeyDoesNotMatchCnf()
    {
        var apKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var wrongKey = AAuthKey.Generate();
        var handler = DiscoveryHandler.For(ApIssuer, AAuthEventsConstants.AgentDwk, Kid, apKey);
        var resolver = CreateResolver(handler);
        var token = new SubscribeTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = Kid,
            Key = apKey,
            ConfirmationKey = agentKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            EventId = "eid-1",
        }.Build().Token;
        using var request = JsonRequest();
        new EventsRequestSigner(wrongKey, () => token, () => EventsTestData.Now)
            .SignRegistration(request);

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            new EventsHttpMessageVerifier { Clock = () => EventsTestData.Now }
                .VerifyAsync(
                    request,
                    resolver,
                    EventsTokenKind.Subscribe,
                    EventsHttpProfile.RegistrationJson,
                    expectedAudience: "https://resource.example"));

        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, error.Error.Code);
    }

    [Fact]
    public async Task ResolverRefreshesChangedKeyAfterSignatureFailure()
    {
        var stale = AAuthKey.Generate();
        var current = AAuthKey.Generate();
        var handler = DiscoveryHandler.ForSequence(
            ResourceIssuer,
            AAuthEventsConstants.ResourceDwk,
            Kid,
            stale,
            current);
        var resolver = CreateResolver(handler);

        var result = await resolver.ResolveEventAsync(
            BuildEvent(current), "aauth:agent@ap.example");

        Assert.Equal(current.ComputeJwkThumbprint(), result.JwtIssuerKey.ComputeJwkThumbprint());
        Assert.Equal(2, handler.JwksRequestCount);
    }

    [Fact]
    public async Task ResolverRefreshesWhenAlgorithmChangedUnderSameKid()
    {
        var stale = AAuthKey.Generate();
        var current = EcdsaAAuthKey.Generate();
        var handler = DiscoveryHandler.ForSequence(
            ResourceIssuer,
            AAuthEventsConstants.ResourceDwk,
            Kid,
            stale,
            current);
        var resolver = CreateResolver(handler);

        var result = await resolver.ResolveEventAsync(
            BuildEvent(current), "aauth:agent@ap.example");

        Assert.Equal("ES256", result.JwtIssuerKey.Algorithm);
        Assert.Equal(2, handler.JwksRequestCount);
    }

    [Fact]
    public async Task DeterministicClaimFailureDoesNotRefreshJwks()
    {
        var key = AAuthKey.Generate();
        var handler = DiscoveryHandler.For(ResourceIssuer, AAuthEventsConstants.ResourceDwk, Kid, key);
        var resolver = CreateResolver(handler);
        var token = RewriteAndResign(
            BuildEvent(key),
            key,
            static (_, payload) => payload.Remove("jti"));

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveEventAsync(token, "aauth:agent@ap.example"));

        Assert.Equal(EventsVerificationErrorCode.InvalidToken, error.Error.Code);
        Assert.Equal(1, handler.JwksRequestCount);
    }

    [Fact]
    public async Task ExpiredAndWrongAudienceTokensDoNotRefreshJwks()
    {
        var key = AAuthKey.Generate();
        var handler = DiscoveryHandler.For(ResourceIssuer, AAuthEventsConstants.ResourceDwk, Kid, key);
        var resolver = CreateResolver(handler);
        var expired = new EventTokenBuilder
        {
            Issuer = ResourceIssuer,
            Audience = "aauth:agent@ap.example",
            Eid = "eid-1",
            KeyId = Kid,
            Key = key,
            IssuedAt = EventsTestData.Now.AddMinutes(-10),
            Lifetime = TimeSpan.FromMinutes(1),
        }.Build().Token;

        var expiredError = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveEventAsync(expired, "aauth:agent@ap.example"));
        Assert.Equal(EventsVerificationErrorCode.ExpiredToken, expiredError.Error.Code);
        Assert.Equal(1, handler.JwksRequestCount);

        var audienceError = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveEventAsync(BuildEvent(key), "aauth:other@ap.example"));
        Assert.Equal(EventsVerificationErrorCode.WrongAudience, audienceError.Error.Code);
        Assert.Equal(1, handler.JwksRequestCount);
    }

    [Fact]
    public async Task ResolverRejectsUnknownKidAndUnsupportedAlgorithm()
    {
        var key = AAuthKey.Generate();
        var handler = DiscoveryHandler.For(
            ResourceIssuer, AAuthEventsConstants.ResourceDwk, "different-kid", key);
        var resolver = CreateResolver(handler);

        var unknown = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveEventAsync(BuildEvent(key), "aauth:agent@ap.example"));
        Assert.Equal(EventsVerificationErrorCode.UnknownKey, unknown.Error.Code);

        var unsupported = RewriteAndResign(
            BuildEvent(key),
            key,
            static (header, _) => header["alg"] = "none");
        var unsupportedError = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveEventAsync(unsupported, "aauth:agent@ap.example"));
        Assert.Equal(EventsVerificationErrorCode.UnsupportedAlgorithm, unsupportedError.Error.Code);
    }

    private static EventsJwtKeyResolver CreateResolver(HttpMessageHandler handler)
    {
        var current = EventsTestData.Now;
        DateTimeOffset Clock()
        {
            current = current.AddSeconds(1);
            return current;
        }
        var http = new HttpClient(handler);
        return new EventsJwtKeyResolver(
            new MetadataClient(http, clock: Clock),
            new JwksClient(
                http,
                cacheTtl: TimeSpan.FromHours(1),
                minRefreshInterval: TimeSpan.Zero,
                clock: Clock),
            new DefaultEventsUrlPolicy(),
            new TokenVerifier
            {
                Clock = () => EventsTestData.Now,
                ClockSkew = TimeSpan.Zero,
            });
    }

    private static string BuildEvent(IAAuthKey key) =>
        new EventTokenBuilder
        {
            Issuer = ResourceIssuer,
            Audience = "aauth:agent@ap.example",
            Eid = "eid-1",
            KeyId = Kid,
            Key = key,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
        }.Build().Token;

    private static HttpRequestMessage JsonRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/waitlist")
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes("""{"event_types":["slot.available"]}""")),
        };
        request.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue(AAuthEventsConstants.JsonMediaType);
        return request;
    }

    private static string RewriteAndResign(
        string compact,
        IAAuthKey key,
        Action<JsonObject, JsonObject> mutate)
    {
        var parts = compact.Split('.');
        var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1]))!.AsObject();
        mutate(header, payload);
        var headerSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = headerSegment + "." + payloadSegment;
        return signingInput + "." +
               Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(signingInput)));
    }

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();

    private sealed class DiscoveryHandler : HttpMessageHandler
    {
        private readonly string _metadataUrl;
        private readonly string _jwksUrl;
        private readonly JsonObject _metadata;
        private readonly Queue<JsonObject> _jwks;

        private DiscoveryHandler(
            string issuer,
            string dwk,
            IEnumerable<JsonObject> jwks)
        {
            _metadataUrl = $"{issuer}/.well-known/{dwk}";
            _jwksUrl = $"{issuer}/jwks";
            _metadata = new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = _jwksUrl,
            };
            _jwks = new Queue<JsonObject>(jwks);
        }

        public int JwksRequestCount { get; private set; }
        public int MetadataRequestCount { get; private set; }

        public static DiscoveryHandler For(
            string issuer,
            string dwk,
            string kid,
            IAAuthKey key) =>
            new(issuer, dwk, [Jwks(kid, key)]);

        public static DiscoveryHandler ForSequence(
            string issuer,
            string dwk,
            string kid,
            params IAAuthKey[] keys) =>
            new(issuer, dwk, keys.Select(key => Jwks(kid, key)));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var url = request.RequestUri?.ToString();
            if (url == _metadataUrl)
            {
                MetadataRequestCount++;
                return Task.FromResult(Json(_metadata));
            }
            if (url == _jwksUrl)
            {
                JwksRequestCount++;
                var document = _jwks.Count > 1 ? _jwks.Dequeue() : _jwks.Peek();
                return Task.FromResult(Json(document));
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static JsonObject Jwks(string kid, IAAuthKey key)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = key.Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) };
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

    private sealed class CountingThrowingDiscoveryHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestCount++;
            throw new InvalidOperationException("Discovery should not be reached for wrong subscribe audiences.");
        }
    }
}
