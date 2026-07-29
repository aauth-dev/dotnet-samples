using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Agent;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests.Conformance;

public sealed class AgentVerificationConformanceTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "L430-L447")]
    [Trait("Spec", "L438-L447")]
    public async Task ValidEventTokenVerifiesAllAgentClaimsAndResourceKey(string algorithm)
    {
        var key = CreateKey(algorithm);
        var token = BuildEvent(key, jti: "jti-1", eid: "eid-1");
        var result = await NewVerifier(key).VerifyAsync(token);

        Assert.Equal(AgentEventVerificationStatus.Verified, result.Status);
        Assert.True(result.IsActionable);
        Assert.Equal("https://resource.example", result.Claims.Issuer);
        Assert.Equal("aauth:agent@ap.example", result.Claims.Audience);
        Assert.Equal("eid-1", result.Claims.Eid);
        Assert.Equal("jti-1", result.Claims.Jti);
        Assert.Equal(EventsTestData.Now, result.Claims.IssuedAt);
        Assert.Equal(EventsTestData.Now.AddMinutes(5), result.Claims.ExpiresAt);
        Assert.Equal("resource-1", result.Claims.KeyId);
        Assert.Equal(token, result.Event!.CompactToken);
        Assert.NotNull(result.Event.VerifiedToken);
    }

    [Theory]
    [InlineData("typ", "not-an-event", EventsVerificationErrorCode.InvalidToken)]
    [InlineData("dwk", "aauth-agent.json", EventsVerificationErrorCode.WrongResource)]
    [Trait("Spec", "L440-L442")]
    public async Task EventProfileRejectsWrongTypeOrDomainKey(
        string claim,
        string value,
        EventsVerificationErrorCode expected)
    {
        var key = AAuthKey.Generate();
        var token = RewriteAndResign(
            BuildEvent(key),
            key,
            (header, payload) =>
            {
                if (claim == "typ")
                    header[AAuthEventsConstants.TypeClaim] = value;
                else
                    payload[AAuthEventsConstants.DomainKeyClaim] = value;
            });

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(key).VerifyAsync(token));

        Assert.Equal(expected, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L440-L442")]
    public async Task EventSignatureMustMatchResourceJwks()
    {
        var trusted = AAuthKey.Generate();
        var forged = AAuthKey.Generate();
        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(trusted).VerifyAsync(BuildEvent(forged)));

        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L440-L442")]
    public async Task UnknownResourceKidIsRejected()
    {
        var key = AAuthKey.Generate();
        var handler = DiscoveryHandler.For(
            "https://resource.example", "different-kid", key);
        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(handler, key).VerifyAsync(BuildEvent(key)));

        Assert.Equal(EventsVerificationErrorCode.UnknownKey, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L440-L442")]
    public async Task RotatedResourceKeyIsRefreshedAndAccepted()
    {
        var oldKey = AAuthKey.Generate();
        var newKey = AAuthKey.Generate();
        var handler = DiscoveryHandler.ForSequence(
            "https://resource.example", "resource-1", oldKey, newKey);

        var result = await NewVerifier(handler, newKey).VerifyAsync(BuildEvent(newKey));

        Assert.True(result.IsActionable);
        Assert.NotNull(result.Event!.VerifiedToken);
        Assert.Equal(2, handler.JwksRequestCount);
    }

    [Fact]
    [Trait("Spec", "L442-L443")]
    public async Task AudienceMustMatchTheAgentIdentifier()
    {
        var key = AAuthKey.Generate();
        var token = BuildEvent(key, audience: "aauth:other-agent@ap.example");
        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(key).VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.WrongAudience, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L443")]
    public async Task FutureIssuedAtIsRejected()
    {
        var key = AAuthKey.Generate();
        var token = BuildEvent(key, issuedAt: EventsTestData.Now.AddMinutes(2));
        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(key).VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.InvalidToken, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L443")]
    public async Task ExpiredEventTokenIsNotActionable()
    {
        var key = AAuthKey.Generate();
        var token = BuildEvent(
            key,
            issuedAt: EventsTestData.Now.AddMinutes(-10),
            lifetime: TimeSpan.FromMinutes(1));
        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(key).VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.ExpiredToken, error.Error.Code);
    }

    [Theory]
    [InlineData("eid")]
    [InlineData("jti")]
    [Trait("Spec", "L444-L445")]
    public async Task RequiredEventIdentifiersAreValidated(string removedClaim)
    {
        var key = AAuthKey.Generate();
        var token = RewriteAndResign(
            BuildEvent(key),
            key,
            (_, payload) => payload.Remove(removedClaim));

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier(key).VerifyAsync(token));

        Assert.Equal(EventsVerificationErrorCode.InvalidToken, error.Error.Code);
    }

    [Fact]
    [Trait("Spec", "L444-L445")]
    public async Task UnknownContextIsTypedAndNonActionable()
    {
        var key = AAuthKey.Generate();
        var verifier = new EventTokenVerifier(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => null));

        var result = await verifier.VerifyAsync(BuildEvent(key, eid: "unknown"));

        Assert.Equal(AgentEventVerificationStatus.UnknownContext, result.Status);
        Assert.False(result.IsActionable);
        Assert.Null(result.Event);
        Assert.NotNull(result.Claims);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "RF2")]
    public async Task ContextLookupPrecedesDeduplication()
    {
        var key = AAuthKey.Generate();
        var known = false;
        var verifier = new EventTokenVerifier(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup((string _) => known ? new object() : null));
        var token = BuildEvent(key);

        Assert.Equal(
            AgentEventVerificationStatus.UnknownContext,
            (await verifier.VerifyAsync(token)).Status);
        known = true;
        Assert.Equal(
            AgentEventVerificationStatus.Verified,
            (await verifier.VerifyAsync(token)).Status);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "C3")]
    [Trait("Spec", "RF2")]
    public async Task DeduplicationHashesTheExactCompactToken()
    {
        var key = AAuthKey.Generate();
        var verifier = NewVerifier(key);
        var first = BuildEvent(key, eid: "same-eid", jti: "jti-one");
        var second = BuildEvent(key, eid: "same-eid", jti: "jti-two");

        var firstResult = await verifier.VerifyAsync(first);
        var secondResult = await verifier.VerifyAsync(second);

        Assert.Equal(AgentEventVerificationStatus.Verified, firstResult.Status);
        Assert.Equal(AgentEventVerificationStatus.Verified, secondResult.Status);
        Assert.NotEqual(firstResult.IdempotencyKey, secondResult.IdempotencyKey);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(first))),
            firstResult.IdempotencyKey);
        Assert.Equal(
            EventTokenVerifier.ComputeIdempotencyKey(second),
            secondResult.IdempotencyKey);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "C14")]
    [Trait("Spec", "RF2")]
    public async Task SameTimeEventsWithSameEidAndDistinctJtiAreBothAccepted()
    {
        var key = AAuthKey.Generate();
        var verifier = NewVerifier(key);
        var first = BuildEvent(key, eid: "same-eid", jti: "first", issuedAt: EventsTestData.Now);
        var second = BuildEvent(key, eid: "same-eid", jti: "second", issuedAt: EventsTestData.Now);

        Assert.Equal(AgentEventVerificationStatus.Verified, (await verifier.VerifyAsync(first)).Status);
        Assert.Equal(AgentEventVerificationStatus.Verified, (await verifier.VerifyAsync(second)).Status);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "C14")]
    [Trait("Spec", "RF2")]
    public async Task ExactTokenReplayIsNonActionable()
    {
        var key = AAuthKey.Generate();
        var verifier = NewVerifier(key);
        var token = BuildEvent(key, jti: "replayed");

        Assert.Equal(AgentEventVerificationStatus.Verified, (await verifier.VerifyAsync(token)).Status);
        var replay = await verifier.VerifyAsync(token);

        Assert.Equal(AgentEventVerificationStatus.Duplicate, replay.Status);
        Assert.False(replay.IsActionable);
        Assert.Null(replay.Event);
    }

    [Fact]
    [Trait("Spec", "L430-L447")]
    [Trait("Spec", "L447")]
    [Trait("Spec", "L600-L617")]
    [Trait("Spec", "L614-L617")]
    [Trait("Spec", "C14")]
    public async Task PayloadSubstitutionLeavesTokenValidButAlwaysUnauthenticated()
    {
        var key = AAuthKey.Generate();
        var token = BuildEvent(key, jti: "payload");
        var original = new UnauthenticatedEventPayload(
            Encoding.UTF8.GetBytes("""{"slot":"original"}"""), "application/json");
        var substituted = new UnauthenticatedEventPayload(
            Encoding.UTF8.GetBytes("""{"slot":"substituted"}"""), "application/json");

        var first = await NewVerifier(key).VerifyAsync(token, original);
        var second = await NewVerifier(key).VerifyAsync(token, substituted);

        Assert.True(first.IsActionable);
        Assert.True(second.IsActionable);
        Assert.Equal(first.Event!.Claims, second.Event!.Claims);
        Assert.Equal(token, second.Event.CompactToken);
        Assert.NotEqual(first.Event.Payload!.GetUtf8Text(), second.Event.Payload!.GetUtf8Text());
        Assert.False(second.Event.Payload.IsAuthenticated);
        Assert.False(second.Event.Payload.IsEndToEndAuthenticated);
        Assert.Equal("Unauthenticated", second.Event.Payload.TrustLabel);
    }

    [Fact]
    [Trait("Spec", "L600-L617")]
    [Trait("Spec", "L614-L617")]
    [Trait("Spec", "C20")]
    public void PayloadOwnsBytesAndPreservesContentType()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"sensitive":"hint"}""");
        var payload = new UnauthenticatedEventPayload(bytes, "application/vnd.example.event+json");
        bytes[0] = 0;
        var returned = payload.Bytes;
        returned[0] = 0;

        Assert.Equal((byte)'{', payload.Bytes[0]);
        Assert.Equal("application/vnd.example.event+json", payload.ContentType);
        Assert.Equal("""{"sensitive":"hint"}""", payload.GetUtf8Text());
    }

    [Fact]
    [Trait("Spec", "L430-L447")]
    [Trait("Spec", "L432")]
    [Trait("Spec", "C23")]
    public void AgentVerifierExposesNoTransportApi()
    {
        var methods = typeof(EventTokenVerifier).GetMethods(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static);

        Assert.DoesNotContain(
            methods,
            method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(HttpClient) ||
                parameter.ParameterType == typeof(HttpRequestMessage)));
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "RF2")]
    public async Task DeduplicatorRecordsOnlyOneConcurrentReplay()
    {
        var deduplicator = new InMemoryEventDeduplicator(capacity: 8);
        var results = await Task.WhenAll(
            Enumerable.Range(0, 128).Select(_ => deduplicator.TryRecordAsync("same-token").AsTask()));

        Assert.Single(results, result => result);
        Assert.Equal(1, deduplicator.Count);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "RF2")]
    public async Task DeduplicatorEvictsOldestAtCapacity()
    {
        var deduplicator = new InMemoryEventDeduplicator(capacity: 2);

        Assert.True(await deduplicator.TryRecordAsync("first"));
        Assert.True(await deduplicator.TryRecordAsync("second"));
        Assert.True(await deduplicator.TryRecordAsync("third"));
        Assert.True(await deduplicator.TryRecordAsync("first"));
        Assert.False(await deduplicator.TryRecordAsync("third"));
        Assert.Equal(2, deduplicator.Count);
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "RF2")]
    public async Task DeduplicatorExpiresKeys()
    {
        var clock = new TestClock(EventsTestData.Now);
        var deduplicator = new InMemoryEventDeduplicator(
            capacity: 2,
            retention: TimeSpan.FromMinutes(1),
            clock: clock.GetUtcNow);

        Assert.True(await deduplicator.TryRecordAsync("expiring"));
        clock.Now = clock.Now.AddMinutes(1);

        Assert.Equal(0, deduplicator.Count);
        Assert.True(await deduplicator.TryRecordAsync("expiring"));
    }

    [Fact]
    [Trait("Spec", "L445")]
    [Trait("Spec", "RF2")]
    public async Task DeduplicatorObservesCancellation()
    {
        var deduplicator = new InMemoryEventDeduplicator();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            deduplicator.TryRecordAsync("cancelled", cancellation.Token).AsTask());
    }

    private static EventTokenVerifier NewVerifier(IAAuthKey key) =>
        new(
            CreateResolver(key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));

    private static EventTokenVerifier NewVerifier(
        DiscoveryHandler handler,
        IAAuthKey key) =>
        new(
            CreateResolver(handler, key),
            "aauth:agent@ap.example",
            new DelegateEventContextLookup(static (string _) => new object()));

    private static string BuildEvent(
        IAAuthKey key,
        string eid = "event-1",
        string? jti = null,
        string audience = "aauth:agent@ap.example",
        DateTimeOffset? issuedAt = null,
        TimeSpan? lifetime = null) =>
        new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = audience,
            Eid = eid,
            KeyId = "resource-1",
            Key = key,
            IssuedAt = issuedAt ?? EventsTestData.Now,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
            Jti = jti,
        }.Build().Token;

    private static EventsJwtKeyResolver CreateResolver(IAAuthKey key) =>
        CreateResolver(DiscoveryHandler.For("https://resource.example", "resource-1", key), key);

    private static EventsJwtKeyResolver CreateResolver(
        DiscoveryHandler handler,
        IAAuthKey key)
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

    private sealed class TestClock
    {
        public TestClock(DateTimeOffset now) => Now = now;
        public DateTimeOffset Now { get; set; }
        public DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class DiscoveryHandler : HttpMessageHandler
    {
        private readonly string _metadataUrl;
        private readonly string _jwksUrl;
        private readonly JsonObject _metadata;
        private readonly Queue<JsonObject> _jwks;

        private DiscoveryHandler(
            string issuer,
            IEnumerable<JsonObject> jwks)
        {
            _metadataUrl = $"{issuer}/.well-known/{AAuthEventsConstants.ResourceDwk}";
            _jwksUrl = $"{issuer}/jwks";
            _metadata = new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = _jwksUrl,
            };
            _jwks = new Queue<JsonObject>(jwks);
        }

        public int JwksRequestCount { get; private set; }

        public static DiscoveryHandler For(
            string issuer,
            string kid,
            IAAuthKey key) =>
            new(issuer, [Jwks(kid, key)]);

        public static DiscoveryHandler ForSequence(
            string issuer,
            string kid,
            params IAAuthKey[] keys) =>
            new(issuer, keys.Select(key => Jwks(kid, key)));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var url = request.RequestUri?.ToString();
            if (url == _metadataUrl)
                return Task.FromResult(Json(_metadata));
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
}
