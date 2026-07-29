using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.AgentProvider;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Events.Tests.AgentProvider;

public sealed class AgentProviderContractTests
{
    [Fact]
    public async Task IssuerRetriesCollisionAndReturnsOnlyPersistedToken()
    {
        var store = new RecordingStore { CollisionCount = 1 };
        var ids = new Queue<string>(new[] { "collision", "fresh" });
        var now = new DateTimeOffset(2026, 7, 15, 7, 0, 0, TimeSpan.Zero);
        var issuer = NewIssuer(store, now, () => ids.Dequeue());

        var artifact = await issuer.IssueAsync();

        Assert.Equal("fresh", artifact.Eid);
        Assert.Equal(2, store.Seen);
        Assert.Equal("fresh", store.Subscription!.Eid);
    }

    [Fact]
    public async Task IssuerAllowsDurableStoreToAuthoritativelyAcceptRepeatedGeneratedId()
    {
        var store = new RecordingStore { CollisionCount = 1 };
        var issuer = NewIssuer(store, EventsTestData.Now, () => "same-id");

        var artifact = await issuer.IssueAsync();

        Assert.Equal("same-id", artifact.Eid);
        Assert.Equal(2, store.Seen);
    }

    [Fact]
    public async Task IssuerStopsAfterConfiguredRetryExhaustion()
    {
        var store = new RecordingStore { CollisionCount = 10 };
        var issuer = NewIssuer(store, EventsTestData.Now, () => Guid.NewGuid().ToString(), retries: 3);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => issuer.IssueAsync());

        Assert.Contains("3 attempts", error.Message);
        Assert.Equal(3, store.Seen);
    }

    [Fact]
    public async Task IssuerPropagatesDurableCreationFailure()
    {
        var store = new RecordingStore { Failure = new InvalidOperationException("durable failure") };
        var issuer = NewIssuer(store, EventsTestData.Now, () => "one");

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => issuer.IssueAsync());

        Assert.Equal("durable failure", error.Message);
        Assert.Equal(1, store.Seen);
    }

    [Fact]
    public async Task IssuerUsesShortTokenLifetimeAndLongerSubscriptionLifetime()
    {
        var now = new DateTimeOffset(2026, 7, 15, 7, 30, 0, TimeSpan.Zero);
        var signingKey = AAuthKey.Generate();
        var confirmationKey = AAuthKey.Generate();
        var store = new RecordingStore();
        var issuer = new SubscribeTokenIssuer(store, new SubscribeTokenIssuerOptions
        {
            Issuer = "https://ap.example",
            Agent = "aauth:agent@example.com",
            Resource = "https://resource.example",
            KeyId = "ap-1",
            Key = signingKey,
            ConfirmationKey = confirmationKey,
            TokenLifetime = TimeSpan.FromMinutes(2),
            SubscriptionLifetime = TimeSpan.FromMinutes(10),
            Clock = () => now,
            EidGenerator = () => "short-lived",
        });

        var artifact = await issuer.IssueAsync();
        var claims = SubscribeTokenClaims.Read(new TokenVerifier
        {
            Clock = () => now,
            ClockSkew = TimeSpan.Zero,
        }.Verify(
            artifact.Token,
            signingKey,
            AAuthEventsConstants.SubscribeTokenType,
            AAuthEventsConstants.AgentDwk,
            "https://resource.example"));

        Assert.Equal(now.AddMinutes(2), claims.ExpiresAt);
        Assert.Equal(now.AddMinutes(10), store.Subscription!.ExpiresAt);
        Assert.Equal("short-lived", store.Subscription.Eid);
    }

    [Fact]
    public async Task IssuerHonorsCancellationBeforeDurableCall()
    {
        var store = new RecordingStore();
        var issuer = NewIssuer(store, EventsTestData.Now, () => "one");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            issuer.IssueAsync(cancellation.Token));

        Assert.Equal(0, store.Seen);
    }

    [Theory]
    [InlineData("TokenLifetime", 0)]
    [InlineData("TokenLifetime", -1)]
    [InlineData("SubscriptionLifetime", 0)]
    [InlineData("SubscriptionLifetime", -1)]
    public void IssuerRejectsNonPositiveTokenAndSubscriptionLifetimes(
        string lifetimeName,
        int seconds)
    {
        var store = new RecordingStore();
        var options = NewIssuerOptions(EventsTestData.Now, () => "one");
        var lifetime = TimeSpan.FromSeconds(seconds);
        if (lifetimeName == "TokenLifetime")
            options.TokenLifetime = lifetime;
        else
            options.SubscriptionLifetime = lifetime;

        Assert.Throws<ArgumentOutOfRangeException>(() => new SubscribeTokenIssuer(store, options));
        Assert.Equal(0, store.Seen);
    }

    [Fact]
    public void AgentProviderRegistrationRequiresDurableStore()
    {
        var services = new ServiceCollection();

        var error = Assert.Throws<InvalidOperationException>(() =>
            services.AddAAuthEventsAgentProvider());

        Assert.Contains(nameof(IAAuthAgentProviderEventStore), error.Message);
    }

    [Fact]
    public void AgentProviderMapRequiresDurableStoreAtStartup()
    {
        var builder = new WebHostBuilder()
            .ConfigureServices(services => services.AddRouting())
            .Configure(app => app.UseRouting().UseEndpoints(endpoints =>
                endpoints.MapAAuthEventEndpoint()));

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var server = new TestServer(builder);
        });
    }

    [Fact]
    public void AgentProviderMapRequiresJwtResolverAtStartup()
    {
        var store = new RecordingStore();
        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAAuthEventsAgentProvider(store);
            })
            .Configure(app => app.UseRouting().UseEndpoints(endpoints =>
                endpoints.MapAAuthEventEndpoint()));

        var error = Assert.Throws<InvalidOperationException>(() =>
        {
            using var server = new TestServer(builder);
        });

        Assert.Contains(nameof(EventsJwtKeyResolver), error.Message);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task EndpointAcceptsVerifiedEventsAndPreservesBodyHeaders(string algorithm)
    {
        var resourceKey = CreateKey(algorithm);
        var store = new RecordingStore
        {
            ResultFactory = incoming => EventAcceptanceResult.Accepted(incoming, 2),
        };
        using var server = CreateServer(resourceKey, store);
        using var client = server.CreateClient();
        using var request = SignedEvent(resourceKey, "eid-1", "event-1", [1, 2, 3]);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("""{"remaining_uses":2}""", await response.Content.ReadAsStringAsync());
        Assert.Equal([1, 2, 3], store.LastIncoming!.RawPayloadBytes);
        Assert.Equal("application/json", store.LastIncoming.ContentType);
        Assert.NotNull(store.LastIncoming.ContentDigest);
        Assert.Equal(1, store.AcceptCalls);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task EndpointAcceptsBodylessEventDeliveries(string algorithm)
    {
        var resourceKey = CreateKey(algorithm);
        var store = new RecordingStore
        {
            ResultFactory = incoming => EventAcceptanceResult.Accepted(incoming),
        };
        using var server = CreateServer(resourceKey, store);
        using var client = server.CreateClient();
        using var request = SignedBodylessEvent(
            resourceKey,
            "eid-bodyless",
            "event-bodyless");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Empty(store.LastIncoming!.RawPayloadBytes);
        Assert.Null(store.LastIncoming.ContentType);
        Assert.Null(store.LastIncoming.ContentDigest);
        Assert.Equal(1, store.AcceptCalls);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task EndpointTreatsContentLengthZeroAsBodyless(string algorithm)
    {
        var resourceKey = CreateKey(algorithm);
        var store = new RecordingStore
        {
            ResultFactory = incoming => EventAcceptanceResult.Accepted(incoming),
        };
        using var server = CreateServer(resourceKey, store);
        using var client = server.CreateClient();
        using var request = SignedBodylessEvent(
            resourceKey,
            "eid-content-length-zero",
            "event-content-length-zero");
        request.Content = new ByteArrayContent([]);
        request.Content.Headers.ContentLength = 0;

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Empty(store.LastIncoming!.RawPayloadBytes);
        Assert.Null(store.LastIncoming.ContentType);
        Assert.Null(store.LastIncoming.ContentDigest);
    }

    [Theory]
    [InlineData(EventAcceptanceOutcome.Accepted, 202)]
    [InlineData(EventAcceptanceOutcome.AlreadyAccepted, 202)]
    [InlineData(EventAcceptanceOutcome.UnknownSubscription, 404)]
    [InlineData(EventAcceptanceOutcome.ExpiredSubscription, 404)]
    [InlineData(EventAcceptanceOutcome.WrongResource, 403)]
    [InlineData(EventAcceptanceOutcome.WrongAudience, 403)]
    [InlineData(EventAcceptanceOutcome.Exhausted, 429)]
    public async Task EndpointMapsEveryAcceptanceOutcome(
        EventAcceptanceOutcome outcome,
        int expectedStatus)
    {
        var resourceKey = AAuthKey.Generate();
        var store = new RecordingStore
        {
            ResultFactory = incoming => outcome is
                EventAcceptanceOutcome.Accepted or EventAcceptanceOutcome.AlreadyAccepted
                ? new EventAcceptanceResult(outcome, incoming, 1)
                : new EventAcceptanceResult(outcome),
        };
        using var server = CreateServer(resourceKey, store);
        using var client = server.CreateClient();
        using var request = SignedEvent(resourceKey, "eid-1", Guid.NewGuid().ToString(), [9]);

        using var response = await client.SendAsync(request);

        Assert.Equal(expectedStatus, (int)response.StatusCode);
        if (expectedStatus == 202)
            Assert.Equal("""{"remaining_uses":1}""", await response.Content.ReadAsStringAsync());
        else
            Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EndpointAcceptedUnlimitedSubscriptionHasNoBody()
    {
        var key = AAuthKey.Generate();
        var store = new RecordingStore
        {
            ResultFactory = incoming => EventAcceptanceResult.Accepted(incoming),
        };
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        using var request = SignedEvent(key, "eid-1", "unlimited", [4]);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EndpointWrongAudienceDoesNotMutateDurableStore()
    {
        var key = AAuthKey.Generate();
        var store = new SubscriptionStore(new AgentProviderSubscription(
            "eid-1", "aauth:agent@ap.example", "https://resource.example", 1,
            EventsTestData.Now.AddMinutes(5)));
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        using var request = SignedEvent(
            key, "eid-1", "wrong-audience", [5], audience: "aauth:other@ap.example");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, store.AcceptCalls);
        Assert.Equal(0, store.Subscription.UseCount);
    }

    [Fact]
    public async Task EndpointRejectsMalformedJwtWithoutStoreMutation()
    {
        var key = AAuthKey.Generate();
        var store = new RecordingStore();
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        using var request = SignedEventWithToken(key, "not-a-jwt");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, store.AcceptCalls);
    }

    [Fact]
    public async Task EndpointRejectsInvalidHttpSignatureWithoutStoreMutation()
    {
        var key = AAuthKey.Generate();
        var store = new RecordingStore();
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        var eventToken = EventToken(key, "eid-1", "invalid-signature").Token;
        using var request = SignedEventWithToken(AAuthKey.Generate(), eventToken);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, store.AcceptCalls);
    }

    [Fact]
    public async Task EndpointRejectsExpiredJwtWithoutStoreMutation()
    {
        var key = AAuthKey.Generate();
        var store = new RecordingStore();
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        var expired = new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:agent@ap.example",
            Eid = "eid-1",
            KeyId = "resource-1",
            Key = key,
            IssuedAt = EventsTestData.Now.AddMinutes(-10),
            Lifetime = TimeSpan.FromMinutes(1),
            Jti = "expired",
        }.Build().Token;
        using var request = SignedEvent(key, "eid-1", expired, [1]);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, store.AcceptCalls);
    }

    [Fact]
    public async Task EndpointPropagatesCancellationFromDurableStore()
    {
        var key = AAuthKey.Generate();
        var store = new RecordingStore
        {
            Failure = new OperationCanceledException(),
        };
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        using var request = SignedEvent(key, "eid-1", "cancelled", [1]);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SendAsync(request));
    }

    [Fact]
    public async Task ConcurrentFinalUseAcceptsExactlyOneEvent()
    {
        var key = AAuthKey.Generate();
        var store = new SubscriptionStore(new AgentProviderSubscription(
            "eid-1", "aauth:agent@ap.example", "https://resource.example", 1,
            EventsTestData.Now.AddMinutes(5)));
        using var server = CreateServer(key, store);
        using var client = server.CreateClient();
        using var first = SignedEvent(key, "eid-1", "concurrent-1", [1]);
        using var second = SignedEvent(key, "eid-1", "concurrent-2", [2]);

        var responses = await Task.WhenAll(client.SendAsync(first), client.SendAsync(second));

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Accepted));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.TooManyRequests));
        Assert.Equal(1, store.Subscription.UseCount);
        foreach (var response in responses) response.Dispose();
    }

    [Fact]
    public void IncomingEventCopiesPayloadAndDigest()
    {
        var claims = new EventTokenClaims(
            "https://resource.example", "aauth:agent@example.com", "eid", "jti",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), "resource-1");
        var payload = new byte[] { 1, 2 };
        var digest = new byte[] { 3, 4 };
        var incoming = new IncomingEvent("header.payload.signature", claims, payload, "application/json", digest);

        payload[0] = 9;
        digest[0] = 9;

        Assert.Equal(new byte[] { 1, 2 }, incoming.RawPayloadBytes);
        Assert.Equal(new byte[] { 3, 4 }, incoming.ContentDigest);
        Assert.Equal(32, incoming.TokenHash.Length);
    }

    private static SubscribeTokenIssuer NewIssuer(
        RecordingStore store,
        DateTimeOffset now,
        Func<string> generator,
        int retries = 8,
        TimeSpan? tokenLifetime = null,
        TimeSpan? subscriptionLifetime = null) =>
        new(store, NewIssuerOptions(now, generator, retries, tokenLifetime, subscriptionLifetime));

    private static SubscribeTokenIssuerOptions NewIssuerOptions(
        DateTimeOffset now,
        Func<string> generator,
        int retries = 8,
        TimeSpan? tokenLifetime = null,
        TimeSpan? subscriptionLifetime = null) =>
        new()
        {
            Issuer = "https://ap.example",
            Agent = "aauth:agent@example.com",
            Resource = "https://resource.example",
            KeyId = "ap-1",
            Key = AAuthKey.Generate(),
            ConfirmationKey = AAuthKey.Generate(),
            TokenLifetime = tokenLifetime ?? TimeSpan.FromMinutes(5),
            SubscriptionLifetime = subscriptionLifetime ?? TimeSpan.FromHours(1),
            Clock = () => now,
            EidGenerator = generator,
            MaxCollisionRetries = retries,
        };

    private static TestServer CreateServer(
        IAAuthKey resourceKey,
        IAAuthAgentProviderEventStore store)
    {
        var resolver = CreateResolver(resourceKey);
        var verifier = new EventsHttpMessageVerifier
        {
            Clock = () => EventsTestData.Now,
            MaxAge = TimeSpan.FromMinutes(5),
        };
        return new TestServer(new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAAuthEventsAgentProvider(store, options =>
                {
                    options.JwtKeyResolver = resolver;
                    options.HttpMessageVerifier = verifier;
                    options.Clock = () => EventsTestData.Now;
                });
            })
            .Configure(app => app.UseRouting().UseEndpoints(endpoints =>
                endpoints.MapAAuthEventEndpoint())));
    }

    private static EventsJwtKeyResolver CreateResolver(IAAuthKey resourceKey)
    {
        var handler = new DiscoveryHandler(resourceKey);
        var http = new HttpClient(handler);
        return new EventsJwtKeyResolver(
            http,
            tokenVerifier: new TokenVerifier
            {
                Clock = () => EventsTestData.Now,
                ClockSkew = TimeSpan.Zero,
            });
    }

    private static HttpRequestMessage SignedEvent(
        IAAuthKey signingKey,
        string eid,
        string tokenOrJti,
        byte[] body,
        string audience = "aauth:agent@ap.example")
    {
        var token = tokenOrJti.Count(c => c == '.') == 2
            ? tokenOrJti
            : EventToken(signingKey, eid, tokenOrJti, audience).Token;
        var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost/events")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(AAuthEventsConstants.JsonMediaType);
        new EventsRequestSigner(signingKey, () => token, () => EventsTestData.Now).SignEvent(request);
        return request;
    }

    private static HttpRequestMessage SignedBodylessEvent(
        IAAuthKey signingKey,
        string eid,
        string jti)
    {
        var token = EventToken(signingKey, eid, jti).Token;
        var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost/events");
        new EventsRequestSigner(signingKey, () => token, () => EventsTestData.Now)
            .SignBodyless(request);
        return request;
    }

    private static HttpRequestMessage SignedEventWithToken(IAAuthKey signingKey, string token) =>
        SignedEventRequest(signingKey, token, [1]);

    private static HttpRequestMessage SignedEventRequest(
        IAAuthKey signingKey,
        string token,
        byte[] body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost/events")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(AAuthEventsConstants.JsonMediaType);
        new EventsRequestSigner(signingKey, () => token, () => EventsTestData.Now).SignEvent(request);
        return request;
    }

    private static EventTokenArtifact EventToken(
        IAAuthKey key,
        string eid,
        string jti,
        string audience = "aauth:agent@ap.example") =>
        new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = audience,
            Eid = eid,
            KeyId = "resource-1",
            Key = key,
            IssuedAt = EventsTestData.Now,
            Lifetime = TimeSpan.FromMinutes(5),
            Jti = jti,
        }.Build();

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();

    private sealed class RecordingStore : IAAuthAgentProviderEventStore
    {
        public int CollisionCount { get; set; }
        public int AcceptCalls { get; private set; }
        public int Seen { get; private set; }
        public AgentProviderSubscription? Subscription { get; private set; }
        public IncomingEvent? LastIncoming { get; private set; }
        public Exception? Failure { get; set; }
        public Func<IncomingEvent, EventAcceptanceResult>? ResultFactory { get; set; }

        public Task<bool> TryCreateSubscriptionAsync(
            AgentProviderSubscription subscription,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Seen++;
            if (Failure is not null) throw Failure;
            if (CollisionCount-- > 0) return Task.FromResult(false);
            Subscription = subscription;
            return Task.FromResult(true);
        }

        public Task<EventAcceptanceResult> AcceptEventAsync(
            IncomingEvent incomingEvent,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AcceptCalls++;
            LastIncoming = incomingEvent;
            if (Failure is not null) throw Failure;
            return Task.FromResult(ResultFactory?.Invoke(incomingEvent) ??
                EventAcceptanceResult.Accepted(incomingEvent));
        }
    }

    private sealed class SubscriptionStore(AgentProviderSubscription subscription)
        : IAAuthAgentProviderEventStore
    {
        private readonly object _gate = new();
        public AgentProviderSubscription Subscription { get; } = subscription;
        public int AcceptCalls { get; private set; }

        public Task<bool> TryCreateSubscriptionAsync(
            AgentProviderSubscription value,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task<EventAcceptanceResult> AcceptEventAsync(
            IncomingEvent incomingEvent,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                AcceptCalls++;
                if (!string.Equals(incomingEvent.Claims.Eid, Subscription.Eid, StringComparison.Ordinal))
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.UnknownSubscription));
                if (!string.Equals(incomingEvent.Claims.Audience, Subscription.Agent, StringComparison.Ordinal))
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongAudience));
                if (!string.Equals(incomingEvent.Claims.Issuer, Subscription.Resource, StringComparison.Ordinal))
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongResource));
                if (Subscription.UseCount >= Subscription.MaxUses)
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.Exhausted));
                Subscription.UseCount++;
                return Task.FromResult(EventAcceptanceResult.Accepted(
                    incomingEvent, Subscription.MaxUses - Subscription.UseCount));
            }
        }
    }

    private sealed class DiscoveryHandler(IAAuthKey key) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var jwks = key.ToPublicJwk();
            jwks["kid"] = "resource-1";
            jwks["use"] = "sig";
            jwks["alg"] = key.Algorithm;
            var body = request.RequestUri?.AbsoluteUri switch
            {
                "https://resource.example/.well-known/aauth-resource.json" =>
                    new JsonObject
                    {
                        ["issuer"] = "https://resource.example",
                        ["jwks_uri"] = "https://resource.example/jwks",
                    },
                "https://resource.example/jwks" =>
                    new JsonObject { ["keys"] = new JsonArray(jwks) },
                _ => null,
            };
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        body.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
                });
        }
    }
}
