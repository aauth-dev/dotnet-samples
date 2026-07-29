using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Agent;
using AAuth.Events.AgentProvider;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Events.Tests.Conformance;

public sealed class EventsEndToEndTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "Events L192-L339; L340-L428; L430-L447; C1; C3; C8")]
    public async Task PublicSubscriptionFlowsFromApIssuanceToResourceDeliveryAndAgent(
        string algorithm)
    {
        using var fixture = new Fixture(algorithm);
        var token = await fixture.IssueAsync(maxUses: 2);
        var registration = await fixture.RegisterPublicAsync(token);

        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        var subscription = Assert.Single(fixture.ResourceSubscriptions);
        Assert.Equal(fixture.AgentId, subscription.AgentSubject);
        Assert.Equal(fixture.ResourceUrl, subscription.ResourceAudience);
        Assert.Equal(token.Eid, subscription.Eid);

        var first = fixture.Delivery.Prepare(
            subscription,
            TimeSpan.FromMinutes(1),
            Encoding.UTF8.GetBytes("""{"event_type":"slot.available","slot":1}"""));
        var firstResult = await fixture.Delivery.SendAsync(first);
        Assert.True(firstResult.IsAccepted);
        Assert.Equal(1, firstResult.RemainingUses);

        var receipt = Assert.Single(fixture.Store.Receipts);
        var verified = await fixture.Agent.VerifyAsync(
            receipt.CompactToken,
            new UnauthenticatedEventPayload(receipt.RawPayloadBytes, receipt.ContentType!));
        Assert.Equal(AgentEventVerificationStatus.Verified, verified.Status);
        Assert.Equal(subscription.Eid, verified.Claims.Eid);
        Assert.Equal(receipt.RawPayloadBytes, verified.Event!.Payload!.Bytes);

        var retry = await fixture.Delivery.SendAsync(first);
        Assert.True(retry.IsAccepted);
        Assert.Equal(1, fixture.Store.MutationCount);
        var duplicate = await fixture.Agent.VerifyAsync(receipt.CompactToken);
        Assert.Equal(AgentEventVerificationStatus.Duplicate, duplicate.Status);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "Events L247-L339; L340-L428; L430-L447; C1; C8")]
    public async Task ProtectedSubscriptionIsAgentBoundAndTicketIsSingleUseUnderRace(
        string algorithm)
    {
        using var fixture = new Fixture(algorithm);
        var ticket = fixture.IssueTicket("ticket-1", fixture.AgentId);
        var wrongToken = await fixture.IssueAsync(subject: "aauth:other@ap.example");
        var wrong = await fixture.RegisterProtectedAsync(ticket, wrongToken);
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);
        Assert.True(fixture.Tickets.Contains(ticket));

        var token = await fixture.IssueAsync();
        var attempts = await Task.WhenAll(
            fixture.RegisterProtectedAsync(ticket, token),
            fixture.RegisterProtectedAsync(ticket, token));

        Assert.Single(attempts, response => response.StatusCode == HttpStatusCode.OK);
        Assert.Single(attempts, response => response.StatusCode == HttpStatusCode.Conflict);
        Assert.False(fixture.Tickets.Contains(ticket));
        Assert.Single(fixture.ResourceSubscriptions);
    }

    [Fact]
    [Trait("Spec", "Events L192; L264-L280; L404-L428; C6; C13; C14")]
    public async Task ApDurabilityBindsResourceAudienceExpiryAndTokenHashAtomically()
    {
        using var fixture = new Fixture("EdDSA");
        var token = await fixture.IssueAsync(maxUses: 1);
        var registration = await fixture.RegisterPublicAsync(token);
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        var subscription = Assert.Single(fixture.ResourceSubscriptions);

        var first = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"));
        var second = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"));
        var results = await Task.WhenAll(
            fixture.Delivery.SendAsync(first),
            fixture.Delivery.SendAsync(second));
        Assert.Single(results, result => result.IsAccepted);
        Assert.Single(results, result => result.IsExhausted);
        Assert.Equal(1, fixture.Store.MutationCount);

        var accepted = fixture.Store.Receipts[0].CompactToken == first.CompactToken
            ? first : second;
        var retry = await fixture.Delivery.SendAsync(accepted);
        Assert.True(retry.IsAccepted);
        Assert.Equal(1, fixture.Store.MutationCount);

        fixture.Store.FailDurableCommit = true;
        var failing = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"));
        var failed = await fixture.Delivery.SendAsync(failing);
        Assert.Equal(EventDeliveryOutcome.Error, failed.Outcome);
        Assert.Equal(1, fixture.Store.MutationCount);

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var incoming = fixture.Store.Receipts[0];
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Store.AcceptEventAsync(incoming, cancelled.Token));
        Assert.Equal(1, fixture.Store.MutationCount);
    }

    [Fact]
    [Trait("Spec", "Events L404-L428; L430-L447; C14; C23; RF2")]
    public async Task SameTimeDistinctJtisAreAcceptedAndEachExactRetryIsIdempotent()
    {
        using var fixture = new Fixture("EdDSA");
        var token = await fixture.IssueAsync();
        await fixture.RegisterPublicAsync(token);
        var subscription = Assert.Single(fixture.ResourceSubscriptions);
        var issuedAt = fixture.Now;
        var first = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"),
            issuedAt: issuedAt);
        var second = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"),
            issuedAt: issuedAt);

        Assert.NotEqual(first.TokenId, second.TokenId);
        var cachedRetry = await fixture.Delivery.SendAsync(first);
        Assert.True(cachedRetry.IsAccepted, $"{cachedRetry.StatusCode} {cachedRetry.Outcome} {cachedRetry.ResponseBody}");
        Assert.True((await fixture.Delivery.SendAsync(second)).IsAccepted);
        Assert.True((await fixture.Delivery.SendAsync(first)).IsAccepted);
        Assert.True((await fixture.Delivery.SendAsync(second)).IsAccepted);
        Assert.Equal(2, fixture.Store.MutationCount);

        var firstAgent = await fixture.Agent.VerifyAsync(first.CompactToken);
        var secondAgent = await fixture.Agent.VerifyAsync(second.CompactToken);
        Assert.Equal(AgentEventVerificationStatus.Verified, firstAgent.Status);
        Assert.Equal(AgentEventVerificationStatus.Verified, secondAgent.Status);
        Assert.Equal(
            AgentEventVerificationStatus.Duplicate,
            (await fixture.Agent.VerifyAsync(first.CompactToken)).Status);
        Assert.Equal(
            AgentEventVerificationStatus.Duplicate,
            (await fixture.Agent.VerifyAsync(second.CompactToken)).Status);
    }

    [Fact]
    [Trait("Spec", "Events L247-L339; C8; RF3")]
    public async Task RegistrationBodyCannotWidenChannelAuthorization()
    {
        using var fixture = new Fixture("EdDSA", rejectBodyWidening: true);
        var token = await fixture.IssueAsync();
        using var response = await fixture.RegisterPublicAsync(
            token, """{"event_types":["admin.secret"]}""");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(fixture.ResourceSubscriptions);
    }

    [Fact]
    [Trait("Spec", "Events L404-L447; L600-L617; C3; RF2")]
    public async Task ApPayloadSubstitutionRemainsTokenValidAndUnauthenticatedAtAgent()
    {
        using var fixture = new Fixture("ES256");
        var token = await fixture.IssueAsync();
        await fixture.RegisterPublicAsync(token);
        var subscription = Assert.Single(fixture.ResourceSubscriptions);
        var delivery = fixture.Delivery.Prepare(
            subscription,
            TimeSpan.FromMinutes(1),
            Encoding.UTF8.GetBytes("""{"value":"signed-by-envelope"}"""));
        Assert.True((await fixture.Delivery.SendAsync(delivery)).IsAccepted);

        var receipt = Assert.Single(fixture.Store.Receipts);
        var substituted = new UnauthenticatedEventPayload(
            Encoding.UTF8.GetBytes("""{"value":"substituted-by-ap"}"""),
            AAuthEventsConstants.JsonMediaType);
        var result = await fixture.Agent.VerifyAsync(delivery.CompactToken, substituted);

        Assert.Equal(AgentEventVerificationStatus.Verified, result.Status);
        Assert.Equal("substituted-by-ap", JsonDocument.Parse(
            result.Event!.Payload!.GetUtf8Text()).RootElement.GetProperty("value").GetString());
        Assert.False(result.Event.Payload.IsAuthenticated);
        Assert.False(result.Event.Payload.IsEndToEndAuthenticated);
        Assert.Equal(receipt.Claims.Jti, result.Claims.Jti);
    }

    [Fact]
    [Trait("Spec", "Events L192; L264-L280; L340-L428; C15")]
    public async Task MetadataCacheRotationEndpointChangeAndUrlPolicyAreIntegrated()
    {
        using var fixture = new Fixture("EdDSA");
        var token = await fixture.IssueAsync();
        await fixture.RegisterPublicAsync(token);
        var subscription = Assert.Single(fixture.ResourceSubscriptions);
        var first = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"));
        Assert.True((await fixture.Delivery.SendAsync(first)).IsAccepted);
        Assert.Equal(1, fixture.ApEventCount("/events"));

        fixture.ApEndpoint = "/events-v2";
        Assert.True((await fixture.Delivery.SendAsync(first)).IsAccepted);
        Assert.Equal(2, fixture.ApEventCount("/events"));
        fixture.DeliveryEndpointResolver.Invalidate(fixture.ApUrl);
        Assert.True((await fixture.Delivery.SendAsync(first)).IsAccepted);
        Assert.Equal(1, fixture.ApEventCount("/events-v2"));

        fixture.RotateResourceKey();
        var rotated = fixture.Delivery.Prepare(
            subscription, TimeSpan.FromMinutes(1), Encoding.UTF8.GetBytes("{}"));
        var rotatedAgentResult = await fixture.CreateAgentVerifier().VerifyAsync(rotated.CompactToken);
        Assert.Equal(AgentEventVerificationStatus.Verified, rotatedAgentResult.Status);
        Assert.True(fixture.ResourceJwksRequestCount >= 1);

        fixture.ApEndpoint = "https://192.168.1.10/events";
        fixture.DeliveryEndpointResolver.Invalidate(fixture.ApUrl);
        await Assert.ThrowsAsync<EventsVerificationException>(() =>
            fixture.Delivery.SendAsync(rotated));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly RouterHandler _router = new();
        private readonly string _algorithm;
        private readonly IAAuthKey _apKey;
        private IAAuthKey _resourceKey;
        private readonly IAAuthKey _agentKey;
        private string _resourceKid = "resource-1";
        private readonly bool _rejectBodyWidening;
        private TestServer? _ap;
        private TestServer? _resource;

        public Fixture(string algorithm, bool rejectBodyWidening = false)
        {
            _algorithm = algorithm;
            _rejectBodyWidening = rejectBodyWidening;
            _apKey = Key(algorithm);
            _resourceKey = Key(algorithm);
            _agentKey = Key(algorithm);
            Store = new DurableStore(() => Now);
            Tickets = new TicketStore();
            var policy = new DefaultEventsUrlPolicy();

            var apResolver = Resolver(policy, () => Now);
            var agentResolver = Resolver(policy, () => Now);
            var registrationVerifier = new SubscriptionRegistrationVerifier(
                apResolver,
                new EventsHttpMessageVerifier { Clock = () => Now, FutureSkew = TimeSpan.Zero });

            _ap = BuildApServer(apResolver);
            _resource = BuildResourceServer(registrationVerifier);
            _router.Ap = _ap.CreateHandler();
            _router.Resource = _resource.CreateHandler();
            ApClient = new HttpClient(_router) { BaseAddress = new Uri(ApUrl) };
            ResourceClient = new HttpClient(_router) { BaseAddress = new Uri(ResourceUrl) };
            DeliveryEndpointResolver = new EventEndpointResolver(
                policy, _router, TimeSpan.FromMinutes(10), () => Now);
            Delivery = new EventDeliveryClient(
                ResourceClient, DeliveryEndpointResolver, _resourceKey, _resourceKid, () => Now);
            Agent = new EventTokenVerifier(
                agentResolver,
                AgentId,
                new DelegateEventContextLookup(eid =>
                {
                    lock (SubscriptionGate)
                        return ResourceSubscriptions.FirstOrDefault(s => s.Eid == eid);
                }));
        }

        public DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);
        public string ApUrl => "https://ap.example";
        public string ResourceUrl => "https://resource.example";
        public string AgentId => "aauth:agent@ap.example";
        public string ApEndpoint { get; set; } = "/events";
        public HttpClient ApClient { get; }
        public HttpClient ResourceClient { get; }
        public EventEndpointResolver DeliveryEndpointResolver { get; }
        public EventDeliveryClient Delivery { get; private set; }
        public EventTokenVerifier Agent { get; }
        public DurableStore Store { get; }
        public TicketStore Tickets { get; }
        public List<ResourceSubscription> ResourceSubscriptions { get; } = [];
        internal object SubscriptionGate { get; } = new();
        public int ResourceJwksRequestCount { get; private set; }

        public async Task<SubscribeTokenArtifact> IssueAsync(
            long? maxUses = null, string? subject = null)
        {
            var issuer = new SubscribeTokenIssuer(Store, new SubscribeTokenIssuerOptions
            {
                Issuer = ApUrl,
                Agent = subject ?? AgentId,
                Resource = ResourceUrl,
                KeyId = "ap-1",
                Key = _apKey,
                ConfirmationKey = _agentKey,
                MaxUses = maxUses,
                TokenLifetime = TimeSpan.FromMinutes(5),
                SubscriptionLifetime = TimeSpan.FromHours(1),
                Clock = () => Now,
            });
            return await issuer.IssueAsync();
        }

        public Task<HttpResponseMessage> RegisterPublicAsync(
            SubscribeTokenArtifact token, string? json = null) =>
            RegisterAsync(new Uri(ResourceUrl + "/public"), token, json);

        public Task<HttpResponseMessage> RegisterProtectedAsync(
            string ticket, SubscribeTokenArtifact token) =>
            RegisterAsync(new Uri(ResourceUrl + "/protected/" + ticket), token, null);

        public string IssueTicket(string ticket, string agent)
        {
            Tickets.Issue(ticket, agent, Now.AddMinutes(5));
            return ticket;
        }

        public int ApEventCount(string path) => Store.EndpointCounts.TryGetValue(path, out var count) ? count : 0;

        public async Task<HttpResponseMessage> SendPreparedAsync(PreparedEventDelivery prepared)
        {
            var endpoint = await DeliveryEndpointResolver.ResolveAsync(ApUrl);
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            new EventsRequestSigner(_resourceKey, () => prepared.CompactToken, () => Now)
                .SignBodyless(request);
            return await ResourceClient.SendAsync(request);
        }

        public void RotateResourceKey()
        {
            _resourceKey = Key(_algorithm);
            _resourceKid = "resource-2";
            Delivery = new EventDeliveryClient(
                ResourceClient, DeliveryEndpointResolver, _resourceKey, _resourceKid, () => Now);
        }

        public EventTokenVerifier CreateAgentVerifier() =>
            new(
                Resolver(new DefaultEventsUrlPolicy(), () => Now),
                AgentId,
                new DelegateEventContextLookup(eid =>
                {
                    lock (SubscriptionGate)
                        return ResourceSubscriptions.FirstOrDefault(s => s.Eid == eid);
                }));

        private Task<HttpResponseMessage> RegisterAsync(
            Uri endpoint, SubscribeTokenArtifact token, string? json)
        {
            var client = new SubscriptionRegistrationClient(
                ResourceClient, _agentKey, () => Now);
            return json is null
                ? SendRegistrationAsync(client, endpoint, token.Token)
                : RegisterJsonFallback(client, endpoint, token.Token, json);
        }

        private async Task<HttpResponseMessage> SendRegistrationAsync(
            SubscriptionRegistrationClient client, Uri endpoint, string token)
        {
            try
            {
                var result = await client.RegisterAsync(endpoint, token);
                return new HttpResponseMessage(result.StatusCode);
            }
            catch (SubscriptionRegistrationClientException exception)
            {
                return new HttpResponseMessage(exception.StatusCode ?? HttpStatusCode.InternalServerError);
            }
        }

        private EventsJwtKeyResolver Resolver(IEventsUrlPolicy policy, Func<DateTimeOffset> clock)
        {
            var http = new HttpClient(_router);
            var verifier = new TokenVerifier { Clock = clock, ClockSkew = TimeSpan.Zero };
            return new EventsJwtKeyResolver(
                new MetadataClient(http, clock: clock),
                new JwksClient(http, minRefreshInterval: TimeSpan.Zero, clock: clock),
                policy,
                verifier);
        }

        private TestServer BuildApServer(EventsJwtKeyResolver resolver)
        {
            var host = new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(Store);
                    services.AddSingleton<IAAuthAgentProviderEventStore>(Store);
                    services.AddSingleton(resolver);
                    services.AddSingleton(new EventsHttpMessageVerifier
                    {
                        Clock = () => Now,
                        FutureSkew = TimeSpan.Zero,
                    });
                })
                .Configure(app => app
                    .Use(async (context, next) =>
                    {
                        Store.EndpointCounts.AddOrUpdate(
                            context.Request.Path.ToString(), 1, static (_, count) => count + 1);
                        try { await next(); }
                        catch (InvalidOperationException)
                        {
                            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                        }
                    })
                    .UseRouting()
                    .UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/.well-known/aauth-agent.json", context =>
                            Metadata(context, ApUrl, ApEndpoint));
                        endpoints.MapGet("/jwks", context => Jwks(context, ApUrl, "ap-1", _apKey));
                        endpoints.MapAAuthEventEndpoint("/events");
                        endpoints.MapAAuthEventEndpoint("/events-v2");
                    }));
            return new TestServer(host);
        }

        private TestServer BuildResourceServer(SubscriptionRegistrationVerifier registrationVerifier)
        {
            var registrationHandler = new RegistrationHandler(this, _rejectBodyWidening);
            var host = new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(registrationVerifier);
                    services.AddSingleton(new EventsHttpMessageVerifier
                    {
                        Clock = () => Now,
                        FutureSkew = TimeSpan.Zero,
                    });
                    services.AddSingleton<IAAuthSubscriptionRegistrationHandler>(registrationHandler);
                })
                .Configure(app => app
                    .UseRouting()
                    .UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/.well-known/aauth-resource.json", context =>
                            Metadata(context, ResourceUrl, "/jwks"));
                        endpoints.MapGet("/jwks", context =>
                        {
                            ResourceJwksRequestCount++;
                            return Jwks(context, ResourceUrl, _resourceKid, _resourceKey);
                        });
                        endpoints.MapAAuthPublicSubscription(
                            SubscriptionChannel.Public(
                                "public", "/public", ["slot.available"], ResourceUrl),
                            registrationHandler);
                        endpoints.MapAAuthProtectedSubscription(
                            SubscriptionChannel.Protected(
                                "protected", "/protected/{ticket}", ["slot.available"], ResourceUrl),
                            registrationHandler);
                    }));
            return new TestServer(host);
        }

        private async Task<HttpResponseMessage> RegisterJsonFallback(
            SubscriptionRegistrationClient client, Uri endpoint, string token, string json)
        {
            try
            {
                var result = await client.RegisterJsonAsync(endpoint, token, json);
                return new HttpResponseMessage(result.StatusCode);
            }
            catch (SubscriptionRegistrationClientException exception)
            {
                return new HttpResponseMessage(exception.StatusCode ?? HttpStatusCode.InternalServerError);
            }
        }

        private static async Task Metadata(HttpContext context, string issuer, string endpoint)
        {
            context.Response.ContentType = AAuthEventsConstants.JsonMediaType;
            await context.Response.WriteAsync(new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = issuer + "/jwks",
                ["event_endpoint"] = endpoint.StartsWith("http", StringComparison.Ordinal)
                    ? endpoint : issuer + endpoint,
            }.ToJsonString());
        }

        private static async Task Jwks(HttpContext context, string issuer, string kid, IAAuthKey key)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["alg"] = key.Algorithm;
            context.Response.ContentType = AAuthEventsConstants.JsonMediaType;
            await context.Response.WriteAsync(new JsonObject
            {
                ["keys"] = new JsonArray(jwk),
            }.ToJsonString());
        }

        private static IAAuthKey Key(string algorithm) =>
            algorithm == "ES256" ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();

        public void Dispose()
        {
            ApClient.Dispose();
            ResourceClient.Dispose();
            _ap?.Dispose();
            _resource?.Dispose();
            _router.Dispose();
        }

        private sealed class RegistrationHandler : IAAuthSubscriptionRegistrationHandler
        {
            private readonly Fixture _fixture;
            private readonly bool _rejectBodyWidening;

            public RegistrationHandler(Fixture fixture, bool rejectBodyWidening)
            {
                _fixture = fixture;
                _rejectBodyWidening = rejectBodyWidening;
            }

            public ValueTask<SubscriptionRegistrationResult> RegisterAsync(
                SubscriptionEndpointContext endpoint,
                VerifiedSubscriptionRegistration registration,
                SignatureUnboundRegistrationBody? preferences,
                CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (endpoint.Descriptor.IsProtected)
                {
                    if (endpoint.Ticket is null)
                        return ValueTask.FromResult(
                            SubscriptionRegistrationResult.Conflict("ticket already used"));
                    var ticket = _fixture.Tickets.MatchAndConsume(
                        endpoint.Ticket,
                        registration.AgentSubject,
                        _fixture.Now);
                    if (ticket == TicketConsumption.WrongAgent)
                        return ValueTask.FromResult(
                            SubscriptionRegistrationResult.Forbidden("ticket is bound to another agent"));
                    if (ticket != TicketConsumption.Consumed)
                        return ValueTask.FromResult(
                            SubscriptionRegistrationResult.Conflict("ticket already used or expired"));
                }

                lock (_fixture.SubscriptionGate)
                {
                    if (_fixture.ResourceSubscriptions.Any(s => s.Eid == registration.Eid))
                        return ValueTask.FromResult(
                            SubscriptionRegistrationResult.Conflict("eid already registered"));
                }
                if (_rejectBodyWidening && preferences is not null)
                    return ValueTask.FromResult(
                        SubscriptionRegistrationResult.Accepted(["admin.secret"]));

                var subscription = ResourceSubscription.FromRegistration(
                    registration, _fixture.Now.AddMinutes(30));
                lock (_fixture.SubscriptionGate)
                    _fixture.ResourceSubscriptions.Add(subscription);
                return ValueTask.FromResult(
                    SubscriptionRegistrationResult.Accepted(["slot.available"]));
            }
        }
    }

    private sealed class RouterHandler : HttpMessageHandler
    {
        public HttpMessageHandler? Ap { get; set; }
        public HttpMessageHandler? Resource { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var handler = request.RequestUri?.Host switch
            {
                "ap.example" => Ap,
                "resource.example" => Resource,
                _ => null,
            };
            if (handler is not null)
            {
                var client = new HttpMessageInvoker(handler, disposeHandler: false);
                return client.SendAsync(request, cancellationToken);
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found)
            {
                Headers = { Location = request.RequestUri },
            });
        }
    }

    private sealed class TicketStore
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, (string Agent, DateTimeOffset Expiry)> _tickets = [];

        public void Issue(string ticket, string agent, DateTimeOffset expiry)
        {
            lock (_gate) _tickets[ticket] = (agent, expiry);
        }

        public bool Contains(string ticket)
        {
            lock (_gate) return _tickets.ContainsKey(ticket);
        }

        public TicketConsumption MatchAndConsume(
            string ticket,
            string agent,
            DateTimeOffset now)
        {
            lock (_gate)
            {
                if (!_tickets.TryGetValue(ticket, out var value))
                    return TicketConsumption.NotFound;
                if (value.Expiry <= now)
                {
                    _tickets.Remove(ticket);
                    return TicketConsumption.Expired;
                }
                if (!string.Equals(value.Agent, agent, StringComparison.Ordinal))
                    return TicketConsumption.WrongAgent;
                _tickets.Remove(ticket);
                return TicketConsumption.Consumed;
            }
        }
    }

    private enum TicketConsumption
    {
        Consumed,
        NotFound,
        Expired,
        WrongAgent,
    }

    private sealed class DurableStore : IAAuthAgentProviderEventStore
    {
        private readonly object _gate = new();
        private readonly Func<DateTimeOffset> _clock;
        private readonly Dictionary<string, AgentProviderSubscription> _subscriptions = [];
        private readonly Dictionary<string, IncomingEvent> _receipts = [];
        public DurableStore(Func<DateTimeOffset> clock) => _clock = clock;
        public bool FailDurableCommit { get; set; }
        public int MutationCount { get; private set; }
        public List<IncomingEvent> Receipts { get; } = [];
        public ConcurrentDictionary<string, int> EndpointCounts { get; } = new();

        public Task<bool> TryCreateSubscriptionAsync(
            AgentProviderSubscription subscription, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_subscriptions.ContainsKey(subscription.Eid)) return Task.FromResult(false);
                _subscriptions.Add(subscription.Eid, subscription);
                return Task.FromResult(true);
            }
        }

        public Task<EventAcceptanceResult> AcceptEventAsync(
            IncomingEvent incomingEvent, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_subscriptions.TryGetValue(incomingEvent.Claims.Eid, out var subscription))
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.UnknownSubscription));
                if (subscription.ExpiresAt <= _clock())
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.ExpiredSubscription));
                if (subscription.Resource != incomingEvent.Claims.Issuer)
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongResource));
                if (subscription.Agent != incomingEvent.Claims.Audience)
                    return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongAudience));
                if (_receipts.TryGetValue(incomingEvent.TokenHashHex, out var prior))
                    return Task.FromResult(EventAcceptanceResult.AlreadyAccepted(
                        prior, Remaining(subscription)));
                if (FailDurableCommit)
                    throw new InvalidOperationException("durable commit failed");
                if (subscription.MaxUses is not null &&
                    subscription.UseCount >= subscription.MaxUses.Value)
                    return Task.FromResult(new EventAcceptanceResult(
                        EventAcceptanceOutcome.Exhausted, RemainingUses: 0));
                subscription.UseCount++;
                var remaining = Remaining(subscription);
                _receipts.Add(incomingEvent.TokenHashHex, incomingEvent);
                Receipts.Add(incomingEvent);
                MutationCount++;
                return Task.FromResult(EventAcceptanceResult.Accepted(incomingEvent, remaining));
            }
        }

        private static long? Remaining(AgentProviderSubscription subscription) =>
            subscription.MaxUses is null
                ? null
                : Math.Max(0, subscription.MaxUses.Value - subscription.UseCount);
    }
}
