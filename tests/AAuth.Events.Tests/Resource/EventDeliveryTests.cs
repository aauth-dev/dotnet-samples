using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using Xunit;

namespace AAuth.Events.Tests.Resource;

public sealed class EventDeliveryTests
{
    private static readonly DateTimeOffset Issued =
        DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);

    [Fact]
    public void FromRegistrationCopiesFactsAndInitializesUses()
    {
        var registration = Registration(maxUses: 2);
        var subscription = ResourceSubscription.FromRegistration(
            registration, registration.ExpiresAt.AddMinutes(-1));

        Assert.Equal(registration.Eid, subscription.Eid);
        Assert.Equal(registration.ApIssuer, subscription.ApIssuer);
        Assert.Equal(registration.AgentSubject, subscription.AgentSubject);
        Assert.Equal(registration.ResourceAudience, subscription.ResourceAudience);
        Assert.Equal(2, subscription.MaxUses);
        Assert.Equal(2, subscription.RemainingUses);
    }

    [Fact]
    public void FromRegistrationAllowsApplicationLifetimeBeyondRegistrationWindow()
    {
        var registration = Registration();
        var subscription = ResourceSubscription.FromRegistration(
            registration, registration.ExpiresAt.AddMinutes(1));

        Assert.Equal(registration.ExpiresAt.AddMinutes(1), subscription.ExpiresAt);
    }

    [Fact]
    public void PreparedPayloadAndReturnedCopiesAreDefensive()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);
        var payload = new byte[] { 1, 2, 3 };
        var prepared = client.Prepare(subscription, TimeSpan.FromMinutes(1), payload);
        payload[0] = 9;
        var returned = prepared.GetPayloadBytes();
        returned[1] = 8;

        Assert.Equal(new byte[] { 1, 2, 3 }, prepared.GetPayloadBytes());
        Assert.Equal(AAuthEventsConstants.JsonMediaType, prepared.ContentType);
    }

    [Fact]
    public void BodylessPreparedDeliveryHasNoContentType()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);
        var prepared = client.Prepare(subscription, TimeSpan.FromMinutes(1));

        Assert.Null(prepared.ContentType);
        Assert.Empty(prepared.GetPayloadBytes());
    }

    [Fact]
    public void PreparationsAtSameTimeHaveDistinctTokens()
    {
        var key = AAuthKey.Generate();
        var subscription = ResourceSubscription.FromRegistration(
            Registration(), Issued.AddMinutes(4));
        var resolver = new AAuth.Events.Discovery.EventEndpointResolver(
            new AAuth.Discovery.MetadataClient(new HttpClient(new NoopHandler())));
        var client = new EventDeliveryClient(
            new HttpClient(new NoopHandler()), resolver, key, "resource-1", () => Issued);

        var first = client.Prepare(subscription, TimeSpan.FromMinutes(1));
        var second = client.Prepare(subscription, TimeSpan.FromMinutes(1));

        Assert.NotEqual(first.TokenId, second.TokenId);
        Assert.NotEqual(first.CompactToken, second.CompactToken);
    }

    [Fact]
    public async Task SendAccepts202WithNoBodyAndEmptyObject()
    {
        var noBody = await SendWithResponse(HttpStatusCode.Accepted, null);
        var emptyObject = await SendWithResponse(HttpStatusCode.Accepted, "{}");

        Assert.True(noBody.IsAccepted);
        Assert.Null(noBody.RemainingUses);
        Assert.True(emptyObject.IsAccepted);
        Assert.Equal("{}", emptyObject.ResponseBody);
    }

    [Fact]
    public async Task SendAcceptsRemainingUsesIncludingZero()
    {
        var result = await SendWithResponse(HttpStatusCode.Accepted, """{"remaining_uses":0}""");

        Assert.Equal(EventDeliveryOutcome.Accepted, result.Outcome);
        Assert.Equal(0, result.RemainingUses);
    }

    [Theory]
    [InlineData(429, "Exhausted")]
    [InlineData(400, "BadRequest")]
    [InlineData(401, "Unauthorized")]
    [InlineData(403, "Forbidden")]
    [InlineData(404, "NotFound")]
    [InlineData(500, "Error")]
    public async Task SendMapsErrorStatusesWithoutSuccessFallback(int status, string outcomeName)
    {
        var result = await SendWithResponse((HttpStatusCode)status, """{"error":"failure"}""");

        Assert.Equal(Enum.Parse<EventDeliveryOutcome>(outcomeName), result.Outcome);
        Assert.False(result.IsAccepted);
        Assert.Equal("""{"error":"failure"}""", result.ResponseBody);
    }

    [Theory]
    [InlineData(202, "[")]
    [InlineData(202, """{"remaining_uses":-1}""")]
    [InlineData(400, "[")]
    [InlineData(429, "[")]
    public async Task SendRejectsMalformedResponseJson(int status, string body)
    {
        var error = await Assert.ThrowsAsync<EventDeliveryProtocolException>(() =>
            SendWithResponse((HttpStatusCode)status, body));

        Assert.Equal((HttpStatusCode)status, error.StatusCode);
        Assert.Equal(body, error.ResponseBody);
    }

    [Fact]
    public async Task SendResolvesEveryTimeAndHonorsMetadataCacheAndInvalidation()
    {
        var metadata = new MetadataHandler(
            "https://events-one.example", "https://events-two.example");
        var transport = new ResponseHandler(HttpStatusCode.Accepted, null);
        var metadataClient = new MetadataClient(
            new HttpClient(metadata), cacheTtl: TimeSpan.FromMinutes(5), clock: () => Issued);
        var resolver = new EventEndpointResolver(metadataClient);
        var client = CreateClient(transport, resolver, AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        await client.SendAsync(prepared);
        await client.SendAsync(prepared);
        Assert.Equal(2, transport.Requests.Count);
        Assert.Equal(1, metadata.CallCount);
        Assert.All(transport.Requests, request =>
            Assert.Equal("events-one.example", request.Uri.Host));

        resolver.Invalidate("https://ap.example");
        await client.SendAsync(prepared);
        Assert.Equal(2, metadata.CallCount);
        Assert.Equal("events-two.example", transport.Requests[2].Uri.Host);
    }

    [Fact]
    public async Task ZeroMetadataTtlRefreshesEndpointOnEachSend()
    {
        var metadata = new MetadataHandler(
            "https://events-one.example", "https://events-two.example");
        var transport = new ResponseHandler(HttpStatusCode.Accepted, null);
        var metadataClient = new MetadataClient(
            new HttpClient(metadata), cacheTtl: TimeSpan.Zero, clock: () => Issued);
        var client = CreateClient(
            transport, new EventEndpointResolver(metadataClient), AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        await client.SendAsync(prepared);
        await client.SendAsync(prepared);

        Assert.Equal(2, metadata.CallCount);
        Assert.Equal("events-one.example", transport.Requests[0].Uri.Host);
        Assert.Equal("events-two.example", transport.Requests[1].Uri.Host);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task ExactRetriesReuseTokenAndBodyAndRemainVerifierValidAfterManyCalls(string algorithm)
    {
        IAAuthKey key = algorithm == "ES256" ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();
        var transport = new ResponseHandler(HttpStatusCode.Accepted, null);
        var now = Issued;
        var client = CreateClient(transport, Resolver(), key, () => now);
        var payload = Encoding.UTF8.GetBytes("""{"slot":"available"}""");
        var prepared = client.Prepare(
            Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1), payload);
        var verifier = new EventsHttpMessageVerifier
        {
            Clock = () => now,
            FutureSkew = TimeSpan.Zero,
        };

        for (var i = 0; i < 8; i++)
        {
            now = Issued.AddSeconds(i);
            var result = await client.SendAsync(prepared);
            Assert.True(result.IsAccepted);
            var request = transport.Requests[i];
            var verified = verifier.VerifyEvent(request.Message, key);
            Assert.Equal(payload, verified.Body);
            Assert.Equal(transport.Requests[0].SignatureKey, request.SignatureKey);
            Assert.Equal(transport.Requests[0].Body, request.Body);
            Assert.Equal(Issued.AddSeconds(i).ToUnixTimeSeconds(),
                ParseCreated(request.SignatureInput));
        }

        Assert.Equal(8, transport.Requests.Count);
        Assert.Equal(8, transport.Requests.Select(r => ParseCreated(r.SignatureInput)).Distinct().Count());
    }

    [Fact]
    public async Task SendPropagatesTransportException()
    {
        var transport = new ResponseHandler(exception: new HttpRequestException("offline"));
        var client = CreateClient(transport, Resolver(), AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(prepared));
    }

    [Fact]
    public async Task SendPropagatesMetadataFailure()
    {
        var resolver = new EventEndpointResolver(new MetadataClient(new HttpClient(new MetadataFailureHandler())));
        var client = CreateClient(
            new ResponseHandler(HttpStatusCode.Accepted, null), resolver, AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() => client.SendAsync(prepared));

        Assert.Equal(EventsVerificationErrorCode.MetadataFailure, error.Error.Code);
    }

    [Fact]
    public async Task SendHonorsCancellationAndHttpTimeout()
    {
        var cancellationTransport = new ResponseHandler(delay: Timeout.InfiniteTimeSpan);
        var cancellationClient = CreateClient(
            cancellationTransport, Resolver(), AAuthKey.Generate(), () => Issued);
        var prepared = cancellationClient.Prepare(
            Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(20));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cancellationClient.SendAsync(prepared, cancellation.Token));

        var timeoutTransport = new ResponseHandler(delay: Timeout.InfiniteTimeSpan);
        using var http = new HttpClient(timeoutTransport)
        {
            Timeout = TimeSpan.FromMilliseconds(20),
        };
        var timeoutClient = new EventDeliveryClient(
            http, Resolver(), AAuthKey.Generate(), "resource-1", () => Issued);
        var timeoutPrepared = timeoutClient.Prepare(
            Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            timeoutClient.SendAsync(timeoutPrepared));
    }

    [Fact]
    public async Task SendRejectsOversizedResponse()
    {
        var transport = new ResponseHandler(
            HttpStatusCode.Accepted,
            new string('x', AAuthEventsConstants.DefaultMaxBodyBytes + 1));
        var client = CreateClient(
            transport, Resolver(), AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(
            Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));

        await Assert.ThrowsAsync<EventDeliveryProtocolException>(() =>
            client.SendAsync(prepared));
    }

    private async Task<EventDeliveryResult> SendWithResponse(
        HttpStatusCode statusCode, string? body)
    {
        var transport = new ResponseHandler(statusCode, body);
        var client = CreateClient(transport, Resolver(), AAuthKey.Generate(), () => Issued);
        var prepared = client.Prepare(Subscription(Issued.AddMinutes(4)), TimeSpan.FromMinutes(1));
        return await client.SendAsync(prepared);
    }

    private static EventEndpointResolver Resolver() =>
        new(new MetadataClient(
            new HttpClient(new MetadataHandler("https://events.example")),
            clock: () => Issued));

    private static EventDeliveryClient CreateClient(
        HttpMessageHandler transport,
        EventEndpointResolver resolver,
        IAAuthKey key,
        Func<DateTimeOffset> clock) =>
        new(new HttpClient(transport), resolver, key, "resource-1", clock);

    private static ResourceSubscription Subscription(DateTimeOffset expiresAt) =>
        ResourceSubscription.FromRegistration(Registration(), expiresAt);

    private static long ParseCreated(string signatureInput)
    {
        const string marker = ";created=";
        var start = signatureInput.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        return long.Parse(signatureInput[start..]);
    }

    private static VerifiedSubscriptionRegistration Registration(long? maxUses = null)
    {
        var key = AAuthKey.Generate();
        return new VerifiedSubscriptionRegistration(
            "https://ap.example",
            "aauth:agent@ap.example",
            "https://resource.example",
            "event-1",
            maxUses,
            key,
            key,
            Issued,
            Issued.AddMinutes(5),
            "ap-1",
            "token");
    }

    private sealed class NoopHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private sealed class MetadataHandler : HttpMessageHandler
    {
        private readonly string[] _endpoints;

        public MetadataHandler(params string[] endpoints) => _endpoints = endpoints;

        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var endpoint = _endpoints[Math.Min(CallCount, _endpoints.Length - 1)];
            CallCount++;
            var body = new JsonObject
            {
                ["issuer"] = "https://ap.example",
                [AAuthEventsConstants.EventEndpointMetadata] = endpoint,
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    body.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            });
        }
    }

    private sealed class MetadataFailureHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }

    private sealed class ResponseHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string? _body;
        private readonly Exception? _exception;
        private readonly TimeSpan? _delay;

        public ResponseHandler(
            HttpStatusCode statusCode = HttpStatusCode.Accepted,
            string? body = null,
            Exception? exception = null,
            TimeSpan? delay = null)
        {
            _statusCode = statusCode;
            _body = body;
            _exception = exception;
            _delay = delay;
        }

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_delay is not null)
                await Task.Delay(_delay.Value, cancellationToken);
            if (_exception is not null)
                throw _exception;
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            var copy = new HttpRequestMessage(request.Method, request.RequestUri);
            foreach (var header in request.Headers)
                copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
            if (request.Content is not null)
            {
                copy.Content = new ByteArrayContent(body);
                foreach (var header in request.Content.Headers)
                    copy.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            Requests.Add(new CapturedRequest(
                copy,
                body,
                request.Headers.GetValues("Signature-Key").Single(),
                request.Headers.GetValues("Signature-Input").Single()));
            return new HttpResponseMessage(_statusCode)
            {
                Content = _body is null
                    ? new ByteArrayContent([])
                    : new StringContent(_body, Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
        }
    }

    private sealed record CapturedRequest(
        HttpRequestMessage Message,
        byte[] Body,
        string SignatureKey,
        string SignatureInput)
    {
        public Uri Uri => Message.RequestUri!;
    }
}
