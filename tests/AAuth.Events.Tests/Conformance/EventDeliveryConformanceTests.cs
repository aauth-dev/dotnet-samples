using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Events.Tests.Conformance;

public sealed class EventDeliveryConformanceTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);

    [Fact]
    [Trait("Spec", "L340-L428")]
    public void EventTokenAndOptionalJsonHaveTheExactWireShape()
    {
        var key = AAuthKey.Generate();
        var payload = Encoding.UTF8.GetBytes("""{"kind":"direct","data":{"n":7}}""");
        var client = CreateClient(new FixedResponseHandler(HttpStatusCode.Accepted, null), key);
        var prepared = client.Prepare(Subscription(), TimeSpan.FromMinutes(1), payload);

        var segments = prepared.CompactToken.Split('.');
        Assert.Equal(3, segments.Length);
        var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(segments[0]))!.AsObject();
        var claims = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(segments[1]))!.AsObject();
        Assert.Equal(["alg", "typ", "kid"], header.Select(static property => property.Key));
        Assert.Equal(
            ["iss", "dwk", "aud", "eid", "iat", "exp", "jti"],
            claims.Select(static property => property.Key));
        Assert.Equal(AAuthEventsConstants.EventTokenType, header["typ"]!.GetValue<string>());
        Assert.Equal(AAuthEventsConstants.ResourceDwk, claims["dwk"]!.GetValue<string>());
        Assert.False(claims.ContainsKey("cnf"));
        Assert.Equal(payload, prepared.GetPayloadBytes());
        Assert.Equal(AAuthEventsConstants.JsonMediaType, prepared.ContentType);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "C3")]
    public async Task EventJwtIsTheHttpSignatureKeyAndDigestCoversExactBytes(string algorithm)
    {
        var key = Key(algorithm);
        var transport = new DurableDeliveryHandler(
            Public(key), Subscription(), Now);
        var payload = new byte[] { 0x7B, 0x22, 0xC3, 0xA9, 0x22, 0x3A, 0x31, 0x7D };
        var client = CreateClient(transport, key);
        var prepared = client.Prepare(Subscription(), TimeSpan.FromMinutes(1), payload);

        var result = await client.SendAsync(prepared);

        Assert.True(result.IsAccepted, $"{result.StatusCode} {result.Outcome} {result.ResponseBody}");
        var request = Assert.Single(transport.Requests);
        var carrier = SignatureKeyHeader.GetJwt(
            request.SignatureKeyHeader);
        Assert.Equal(prepared.CompactToken, carrier);
        Assert.Equal(payload, request.Body);
        Assert.Equal(
            $"sha-256=:{Convert.ToBase64String(SHA256.HashData(payload))}:",
            request.ContentDigest);
    }

    [Fact]
    [Trait("Spec", "Events §AP Validation L402-L413")]
    public async Task ApVerifiesTokenThenHttpThenSubscriptionBeforeDurableMutation()
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        store.Add(Subscription(maxUses: 1));
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);

        var result = await client.SendAsync(
            client.Prepare(Subscription(maxUses: 1), TimeSpan.FromMinutes(1)));

        Console.WriteLine($"RESULT {result.StatusCode} {result.Outcome} {result.ResponseBody} ORDER {string.Join(',', transport.Order)}");
        Assert.True(result.IsAccepted, $"{result.StatusCode} {result.Outcome} {result.ResponseBody}");
        Assert.Equal(["jwt", "http", "lookup", "iss", "aud", "commit"], transport.Order);
        Assert.Equal(1, store.MutationCount);
    }

    [Fact]
    [Trait("Spec", "C6")]
    public async Task UnknownSubscriptionIsNotActionableAndDoesNotMutateDurableState()
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);

        var result = await client.SendAsync(
            client.Prepare(Subscription(), TimeSpan.FromMinutes(1)));

        Assert.Equal(EventDeliveryOutcome.NotFound, result.Outcome);
        Assert.Equal(0, store.MutationCount);
    }

    [Fact]
    [Trait("Spec", "C6")]
    public async Task ExpiredSubscriptionIsNotActionableAndDoesNotMutateDurableState()
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        store.Add(Subscription(), expiresAt: Now.AddSeconds(-1));
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);

        var result = await client.SendAsync(
            client.Prepare(Subscription(), TimeSpan.FromMinutes(1)));

        Assert.Equal(EventDeliveryOutcome.NotFound, result.Outcome);
        Assert.Equal(0, store.MutationCount);
    }

    [Fact]
    [Trait("Spec", "C13")]
    public async Task WrongResourceAndAudienceAreRejectedBeforeMutation()
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        store.Add(Subscription());
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var endpoint = new Uri("https://events.example/events");

        var wrongResource = EventToken(
            key, issuer: "https://other-resource.example", audience: "aauth:agent@ap.example");
        var wrongResourceResponse = await SendRawAsync(
            transport, endpoint, wrongResource, key, Encoding.UTF8.GetBytes("{}"));
        var wrongAudience = EventToken(
            key, issuer: "https://resource.example", audience: "aauth:other@ap.example");
        var wrongAudienceResponse = await SendRawAsync(
            transport, endpoint, wrongAudience, key, Encoding.UTF8.GetBytes("{}"));

        Assert.Equal(HttpStatusCode.Forbidden, wrongResourceResponse);
        Assert.Equal(HttpStatusCode.Forbidden, wrongAudienceResponse);
        Assert.Equal(0, store.MutationCount);
    }

    [Theory]
    [InlineData(-120, 10)]
    [InlineData(120, 10)]
    [Trait("Spec", "C14")]
    public async Task ExpiredAndFutureEventTokensAreRejectedWithoutMutation(
        int issueOffsetSeconds, int lifetimeSeconds)
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        store.Add(Subscription());
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var token = EventToken(
            key,
            issuer: "https://resource.example",
            audience: "aauth:agent@ap.example",
            issuedAt: Now.AddSeconds(issueOffsetSeconds),
            lifetime: TimeSpan.FromSeconds(lifetimeSeconds));

        var status = await SendRawAsync(
            transport, new Uri("https://events.example/events"), token, key, Encoding.UTF8.GetBytes("{}"));

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(0, store.MutationCount);
    }

    [Fact]
    [Trait("Spec", "C20")]
    public async Task ConcurrentDistinctFinalUsesAllowOnlyOneDurableCommit()
    {
        var key = AAuthKey.Generate();
        var subscription = Subscription(maxUses: 1);
        var store = new DurableSubscriptionStore();
        store.Add(subscription);
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);
        var first = client.Prepare(subscription, TimeSpan.FromMinutes(1));
        var second = client.Prepare(subscription, TimeSpan.FromMinutes(1));

        var results = await Task.WhenAll(client.SendAsync(first), client.SendAsync(second));

        Assert.Equal(1, results.Count(static result => result.IsAccepted));
        Assert.Equal(1, results.Count(static result => result.IsExhausted));
        Assert.Equal(1, store.MutationCount);
        Assert.Equal(0, store.RemainingUses);
    }

    [Fact]
    [Trait("Spec", "C20")]
    public async Task DurableFailureNeverReturns202OrConsumesAUse()
    {
        var key = AAuthKey.Generate();
        var subscription = Subscription(maxUses: 1);
        var store = new DurableSubscriptionStore { FailCommits = true };
        store.Add(subscription);
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);

        var result = await client.SendAsync(
            client.Prepare(subscription, TimeSpan.FromMinutes(1)));

        Assert.Equal(EventDeliveryOutcome.Error, result.Outcome);
        Assert.Equal(HttpStatusCode.InternalServerError, result.StatusCode);
        Assert.False(result.IsAccepted);
        Assert.Equal(0, store.MutationCount);
        Assert.Equal(1, store.RemainingUses);
    }

    [Fact]
    [Trait("Spec", "C23")]
    public async Task ExactRetryIsIdempotentAndConsumesAtMostOneUse()
    {
        var key = AAuthKey.Generate();
        var subscription = Subscription(maxUses: 1);
        var store = new DurableSubscriptionStore();
        store.Add(subscription);
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);
        var prepared = client.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("""{"retry":true}"""));

        var first = await client.SendAsync(prepared);
        var second = await client.SendAsync(prepared);

        Assert.True(first.IsAccepted);
        Assert.True(second.IsAccepted);
        Assert.Equal(0, first.RemainingUses);
        Assert.Equal(0, second.RemainingUses);
        Assert.Equal(1, store.MutationCount);
        Assert.Equal(2, transport.Requests.Count);
        Assert.Equal(transport.Requests[0].Token, transport.Requests[1].Token);
        Assert.Equal(transport.Requests[0].Body, transport.Requests[1].Body);
    }

    [Fact]
    [Trait("Spec", "C23")]
    public async Task DistinctEventsPreparedAtTheSameTimeHaveDistinctJtiAndBothApply()
    {
        var key = AAuthKey.Generate();
        var store = new DurableSubscriptionStore();
        store.Add(Subscription());
        var transport = new DurableDeliveryHandler(Public(key), store, Now);
        var client = CreateClient(transport, key);
        var first = client.Prepare(Subscription(), TimeSpan.FromMinutes(1));
        var second = client.Prepare(Subscription(), TimeSpan.FromMinutes(1));

        await client.SendAsync(first);
        await client.SendAsync(second);

        Assert.NotEqual(first.TokenId, second.TokenId);
        Assert.Equal(2, store.MutationCount);
        Assert.Equal(2, transport.Requests.Select(static request => request.Token).Distinct().Count());
    }

    [Fact]
    [Trait("Spec", "Events §Event Token L348-L359; C23")]
    public void EventIssuanceAddsFreshRandomJtiForTokenIdentity()
    {
        var key = AAuthKey.Generate();
        var first = EventsTestData.Event(key).Token;
        var second = EventsTestData.Event(key).Token;
        var firstJti = DecodeToken(first).Payload["jti"]!.GetValue<string>();
        var secondJti = DecodeToken(second).Payload["jti"]!.GetValue<string>();

        Assert.NotEqual(firstJti, secondJti);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(firstJti).Length);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(secondJti).Length);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("{}", null)]
    [InlineData("""{"remaining_uses":0}""", "0")]
    [InlineData("""{"remaining_uses":3}""", "3")]
    [Trait("Spec", "L340-L428")]
    public async Task AcceptedResponsesAllowNoBodyEmptyObjectAndRemainingUses(
        string? body, string? expectedRemaining)
    {
        var key = AAuthKey.Generate();
        var transport = new FixedResponseHandler(HttpStatusCode.Accepted, body);
        var result = await CreateClient(transport, key).SendAsync(
            CreateClient(transport, key).Prepare(Subscription(), TimeSpan.FromMinutes(1)));

        Assert.True(result.IsAccepted);
        Assert.Equal(string.IsNullOrWhiteSpace(body) ? null : body, result.ResponseBody);
        Assert.Equal(
            expectedRemaining is null ? null : long.Parse(expectedRemaining),
            result.RemainingUses);
    }

    [Theory]
    [InlineData(429, EventDeliveryOutcome.Exhausted)]
    [InlineData(400, EventDeliveryOutcome.BadRequest)]
    [InlineData(401, EventDeliveryOutcome.Unauthorized)]
    [InlineData(403, EventDeliveryOutcome.Forbidden)]
    [InlineData(404, EventDeliveryOutcome.NotFound)]
    [Trait("Spec", "C23")]
    public async Task DeliveryMapsProtocolStatusesWithoutSuccessFallback(
        int status, EventDeliveryOutcome expected)
    {
        var key = AAuthKey.Generate();
        var transport = new FixedResponseHandler(
            (HttpStatusCode)status, """{"error":"not-accepted"}""");
        var client = CreateClient(transport, key);

        var result = await client.SendAsync(
            client.Prepare(Subscription(), TimeSpan.FromMinutes(1)));

        Assert.Equal(expected, result.Outcome);
        Assert.Equal((HttpStatusCode)status, result.StatusCode);
        Assert.False(result.IsAccepted);
        Assert.Equal("""{"error":"not-accepted"}""", result.ResponseBody);
    }

    [Fact]
    [Trait("Spec", "D17")]
    public async Task EndpointMetadataIsCachedAndExplicitInvalidationRefreshesIt()
    {
        var key = AAuthKey.Generate();
        var metadata = new MetadataHandler(
            "https://events-one.example/events", "https://events-two.example/events");
        var transport = new FixedResponseHandler(HttpStatusCode.Accepted, null);
        var resolver = Resolver(metadata, TimeSpan.FromMinutes(5));
        var client = new EventDeliveryClient(
            new HttpClient(transport), resolver, key, "resource-1", () => Now);
        var prepared = client.Prepare(Subscription(), TimeSpan.FromMinutes(1));

        await client.SendAsync(prepared);
        await client.SendAsync(prepared);
        resolver.Invalidate("https://ap.example");
        await client.SendAsync(prepared);

        Assert.Equal(2, metadata.CallCount);
        Assert.Equal(
            ["events-one.example", "events-one.example", "events-two.example"],
            transport.RequestUris.Select(static uri => uri.Host));
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "C23")]
    public async Task ARetryReusesTheExactTokenAndBodyForEitherAllowedAlgorithm(string algorithm)
    {
        var key = Key(algorithm);
        var transport = new SequenceResponseHandler(
            ((HttpStatusCode)500, """{"error":"retry"}"""),
            (HttpStatusCode.Accepted, null));
        var client = CreateClient(transport, key);
        var payload = Encoding.UTF8.GetBytes("""{"bytes":[0,1,255]}""");
        var prepared = client.Prepare(Subscription(), TimeSpan.FromMinutes(1), payload);

        await client.SendAsync(prepared);
        var result = await client.SendAsync(prepared);

        Assert.True(result.IsAccepted);
        Assert.Equal(2, transport.Requests.Count);
        Assert.Equal(transport.Requests[0].Token, transport.Requests[1].Token);
        Assert.Equal(payload, transport.Requests[0].Body);
        Assert.Equal(payload, transport.Requests[1].Body);
        Assert.Equal(algorithm, ParseHeaderAlgorithm(prepared.CompactToken));
    }

    [Fact]
    [Trait("Spec", "C14")]
    public async Task CancellationStopsDeliveryBeforeAnOutcomeIsProduced()
    {
        var key = AAuthKey.Generate();
        var transport = new BlockingHandler();
        var client = CreateClient(transport, key);
        var prepared = client.Prepare(Subscription(), TimeSpan.FromMinutes(1));
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(25));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.SendAsync(prepared, cancellation.Token));
        Assert.True(transport.CancellationObserved);
    }

    private static EventDeliveryClient CreateClient(
        HttpMessageHandler transport,
        IAAuthKey key,
        DateTimeOffset? clock = null)
    {
        var resolver = Resolver();
        return new EventDeliveryClient(
            new HttpClient(transport), resolver, key, "resource-1", () => clock ?? Now);
    }

    private static EventEndpointResolver Resolver(
        MetadataHandler? metadata = null,
        TimeSpan? cacheTtl = null) =>
        new(new MetadataClient(
            new HttpClient(metadata ?? new MetadataHandler("https://events.example/events")),
            cacheTtl: cacheTtl,
            clock: () => Now));

    private static IAAuthKey Key(string algorithm) =>
        algorithm == "ES256" ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();

    private static IAAuthKey Public(IAAuthKey key) =>
        KeyFactory.FromJwk(key.ToPublicJwk());

    private static ResourceSubscription Subscription(long? maxUses = null) =>
        new(
            "event-1",
            "https://ap.example",
            "aauth:agent@ap.example",
            "https://resource.example",
            maxUses,
            Now.AddMinutes(5));

    private static string EventToken(
        IAAuthKey key,
        string issuer,
        string audience,
        DateTimeOffset? issuedAt = null,
        TimeSpan? lifetime = null) =>
        new EventTokenBuilder
        {
            Issuer = issuer,
            Audience = audience,
            Eid = "event-1",
            KeyId = "resource-1",
            Key = key,
            IssuedAt = issuedAt ?? Now,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(1),
        }.Build().Token;

    private static async Task<HttpStatusCode> SendRawAsync(
        HttpMessageHandler handler,
        Uri endpoint,
        string token,
        IAAuthKey key,
        byte[] payload)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new ByteArrayContent(payload),
        };
        request.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue(AAuthEventsConstants.JsonMediaType);
        new EventsRequestSigner(key, () => token, () => Now).SignEvent(request);
        using var http = new HttpClient(handler);
        using var response = await http.SendAsync(request);
        return response.StatusCode;
    }

    private static string ParseHeaderAlgorithm(string token)
    {
        var json = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]))!.AsObject();
        return json["alg"]!.GetValue<string>();
    }

    private static (JsonObject Header, JsonObject Payload) DecodeToken(string token) =>
        (
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]))!.AsObject(),
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject()
        );

    private sealed class DurableSubscriptionStore
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

        public bool FailCommits { get; init; }
        public int MutationCount { get; private set; }
        public long? RemainingUses
        {
            get
            {
                lock (_gate)
                    return _entries.Values.SingleOrDefault()?.Remaining;
            }
        }

        public void Add(ResourceSubscription subscription, DateTimeOffset? expiresAt = null)
        {
            lock (_gate)
            {
                _entries[subscription.Eid] = new Entry(
                    subscription.ResourceAudience,
                    subscription.AgentSubject,
                    expiresAt ?? subscription.ExpiresAt,
                    subscription.RemainingUses,
                    new HashSet<string>(StringComparer.Ordinal));
            }
        }

        public CommitResult Commit(
            string eid,
            string jti,
            string issuer,
            string audience,
            Action<string> recordStep,
            DateTimeOffset now)
        {
            lock (_gate)
            {
                if (!_entries.TryGetValue(eid, out var entry))
                    return CommitResult.Unknown;
                if (entry.ExpiresAt <= now)
                    return CommitResult.Expired;
                recordStep("iss");
                if (!string.Equals(issuer, entry.AuthorizedResource, StringComparison.Ordinal))
                    return CommitResult.WrongResource;
                recordStep("aud");
                if (!string.Equals(audience, entry.AuthorizedAgent, StringComparison.Ordinal))
                    return CommitResult.WrongAudience;
                if (entry.Seen.Contains(jti))
                    return new CommitResult(CommitKind.Duplicate, entry.Remaining);
                if (FailCommits)
                    return CommitResult.Failed;
                if (entry.Remaining is 0)
                    return CommitResult.Exhausted;
                entry.Seen.Add(jti);
                if (entry.Remaining is not null)
                    entry.Remaining--;
                MutationCount++;
                return new CommitResult(CommitKind.Accepted, entry.Remaining);
            }
        }

        private sealed class Entry(
            string authorizedResource,
            string authorizedAgent,
            DateTimeOffset expiresAt,
            long? remaining,
            HashSet<string> seen)
        {
            public string AuthorizedResource { get; } = authorizedResource;
            public string AuthorizedAgent { get; } = authorizedAgent;
            public DateTimeOffset ExpiresAt { get; } = expiresAt;
            public long? Remaining { get; set; } = remaining;
            public HashSet<string> Seen { get; } = seen;
        }
    }

    private sealed class DurableDeliveryHandler : HttpMessageHandler
    {
        private readonly IAAuthKey _resourcePublicKey;
        private readonly DurableSubscriptionStore _store;
        private readonly DateTimeOffset _now;
        private readonly EventsHttpMessageVerifier _httpVerifier;
        private readonly TokenVerifier _tokenVerifier;

        public DurableDeliveryHandler(
            IAAuthKey resourcePublicKey,
            ResourceSubscription subscription,
            DateTimeOffset now) : this(resourcePublicKey, new DurableSubscriptionStore(), now)
        {
            _store.Add(subscription);
        }

        public DurableDeliveryHandler(
            IAAuthKey resourcePublicKey,
            DurableSubscriptionStore store,
            DateTimeOffset now)
        {
            _resourcePublicKey = resourcePublicKey;
            _store = store;
            _now = now;
            _httpVerifier = new EventsHttpMessageVerifier
            {
                Clock = () => now,
                FutureSkew = TimeSpan.Zero,
            };
            _tokenVerifier = new TokenVerifier
            {
                Clock = () => now,
                ClockSkew = TimeSpan.Zero,
            };
        }

        public List<CapturedRequest> Requests { get; } = [];
        private readonly object _requestGate = new();
        public ConcurrentQueue<string> OrderQueue { get; } = new();
        public IReadOnlyList<string> Order => OrderQueue.ToArray();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            var header = request.Headers.GetValues(SignatureKeyHeader.Name).Single();
            var token = SignatureKeyHeader.GetJwt(header);
            lock (_requestGate)
            {
                Requests.Add(new CapturedRequest(
                    request,
                    token ?? string.Empty,
                    body,
                    header,
                    request.Content?.Headers.TryGetValues("Content-Digest", out var digest) == true
                        ? digest.Single()
                        : null));
            }
            try
            {
                if (token is null)
                    return Json(HttpStatusCode.Unauthorized, """{"error":"missing-token"}""");
                OrderQueue.Enqueue("jwt");
                var verified = _tokenVerifier.Verify(
                    token,
                    _resourcePublicKey,
                    AAuthEventsConstants.EventTokenType,
                    AAuthEventsConstants.ResourceDwk);
                var claims = EventTokenClaims.Read(verified);

                OrderQueue.Enqueue("http");
                if (request.Content is null)
                    _httpVerifier.VerifyBodyless(request, _resourcePublicKey);
                else
                    _httpVerifier.VerifyEvent(request, _resourcePublicKey);
                OrderQueue.Enqueue("lookup");
                var committed = _store.Commit(
                    claims.Eid,
                    claims.Jti,
                    claims.Issuer,
                    claims.Audience,
                    OrderQueue.Enqueue,
                    _now);
                return committed.Kind switch
                {
                    CommitKind.Unknown or CommitKind.Expired =>
                        Json(HttpStatusCode.NotFound, """{"error":"subscription"}"""),
                    CommitKind.WrongResource =>
                        Json(HttpStatusCode.Forbidden, """{"error":"wrong-resource"}"""),
                    CommitKind.WrongAudience =>
                        Json(HttpStatusCode.Forbidden, """{"error":"wrong-audience"}"""),
                    CommitKind.Exhausted =>
                        Json((HttpStatusCode)429, """{"error":"exhausted"}"""),
                    CommitKind.Failed =>
                        Json(HttpStatusCode.InternalServerError, """{"error":"durable-store"}"""),
                    CommitKind.Duplicate or CommitKind.Accepted => Accepted(committed.Remaining),
                    _ => throw new InvalidOperationException(),
                };
            }
            catch (TokenVerificationException)
            {
                return Json(HttpStatusCode.Unauthorized, """{"error":"token"}""");
            }
            catch (EventsVerificationException)
            {
                return Json(HttpStatusCode.BadRequest, """{"error":"http"}""");
            }
        }

        private HttpResponseMessage Accepted(long? remaining)
        {
            OrderQueue.Enqueue("commit");
            if (remaining is null)
                return Json(HttpStatusCode.Accepted, null);
            return Json(
                HttpStatusCode.Accepted,
                JsonSerializer.Serialize(new { remaining_uses = remaining.Value }));
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string? body) =>
            new(status)
            {
                Content = body is null
                    ? new ByteArrayContent([])
                    : new StringContent(body, Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
    }

    private sealed class FixedResponseHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string? _body;

        public FixedResponseHandler(HttpStatusCode status, string? body)
        {
            _status = status;
            _body = body;
        }

        public List<Uri> RequestUris { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestUris.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = _body is null
                    ? new ByteArrayContent([])
                    : new StringContent(_body, Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            });
        }
    }

    private sealed class SequenceResponseHandler : HttpMessageHandler
    {
        private readonly (HttpStatusCode Status, string? Body)[] _responses;
        private int _index;

        public SequenceResponseHandler(
            params (HttpStatusCode Status, string? Body)[] responses) =>
            _responses = responses;

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            var token = SignatureKeyHeader.GetJwt(
                request.Headers.GetValues(SignatureKeyHeader.Name).Single())!;
            Requests.Add(new CapturedRequest(
                request, token, body,
                request.Headers.GetValues(SignatureKeyHeader.Name).Single(),
                request.Content?.Headers.TryGetValues("Content-Digest", out var digest) == true
                    ? digest.Single()
                    : null));
            var response = _responses[Math.Min(
                Interlocked.Increment(ref _index) - 1, _responses.Length - 1)];
            return new HttpResponseMessage(response.Status)
            {
                Content = response.Body is null
                    ? new ByteArrayContent([])
                    : new StringContent(
                        response.Body, Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
        }
    }

    private sealed class MetadataHandler : HttpMessageHandler
    {
        private readonly string[] _endpoints;

        public MetadataHandler(params string[] endpoints) => _endpoints = endpoints;
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var endpoint = _endpoints[Math.Min(CallCount, _endpoints.Length - 1)];
            CallCount++;
            var document = new JsonObject
            {
                ["issuer"] = "https://ap.example",
                [AAuthEventsConstants.EventEndpointMetadata] = endpoint,
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    document.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            });
        }
    }

    private sealed class BlockingHandler : HttpMessageHandler
    {
        public bool CancellationObserved { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                CancellationObserved = true;
                throw;
            }

            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    private sealed record CapturedRequest(
        HttpRequestMessage Message,
        string Token,
        byte[] Body,
        string SignatureKeyHeader,
        string? ContentDigest);

    private enum CommitKind
    {
        Unknown,
        Expired,
        WrongResource,
        WrongAudience,
        Exhausted,
        Failed,
        Duplicate,
        Accepted,
    }

    private sealed record CommitResult(CommitKind Kind, long? Remaining = null)
    {
        public static CommitResult Unknown { get; } = new(CommitKind.Unknown);
        public static CommitResult Expired { get; } = new(CommitKind.Expired);
        public static CommitResult WrongResource { get; } = new(CommitKind.WrongResource);
        public static CommitResult WrongAudience { get; } = new(CommitKind.WrongAudience);
        public static CommitResult Exhausted { get; } = new(CommitKind.Exhausted);
        public static CommitResult Failed { get; } = new(CommitKind.Failed);
    }
}
