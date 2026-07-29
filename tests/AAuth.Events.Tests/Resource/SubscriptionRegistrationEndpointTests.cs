using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Discovery;
using AAuth.Events.Resource;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Events.Tests.Resource;

public sealed class SubscriptionRegistrationEndpointTests
{
    private const string ResourceAudience = "https://resource.example";

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task PublicRegistrationAcceptsValidToken(string algorithm)
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, _, _, _) =>
        {
            calls++;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/public", fixture.Token(algorithm), fixture.AgentKey(algorithm));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task ProtectedRegistrationAcceptsPathBaseAndEscapedTicket(string algorithm)
    {
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        string? ticket = null;
        using var fixture = new Fixture(channel, (endpoint, _, _, _) =>
        {
            ticket = endpoint.Ticket;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/api/channel/ticket%2Dencoded", fixture.Token(algorithm), fixture.AgentKey(algorithm));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ticket-encoded", ticket);
    }

    [Fact]
    public async Task VerificationFailureDoesNotInvokeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            calls++;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/public", fixture.Token("EdDSA", audience: "https://other.example"), fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task WrongCnfHttpKeyDoesNotInvokeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            calls++;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/api/channel/ticket", fixture.Token("EdDSA"), AAuthKey.Generate());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task WrongResourceAndExpiredTokensDoNotInvokeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            calls++;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var wrongResource = await fixture.PostAsync(
            "/public", fixture.WrongResourceToken(), fixture.AgentKey("EdDSA"));
        using var expired = await fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA", issuedAt: EventsTestData.Now.AddMinutes(-10), lifetime: TimeSpan.FromMinutes(1)),
            fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.Forbidden, wrongResource.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void InvalidChannelAudienceFailsImmediately(string? audience)
    {
        Assert.Throws<ArgumentException>(() =>
            SubscriptionChannel.Public("public", "/public", ["slot.available"], audience!));
        Assert.Throws<ArgumentException>(() =>
            SubscriptionChannel.Protected("protected", "/channel/{ticket}", ["slot.available"], audience!));
        Assert.Throws<ArgumentException>(() =>
            new SubscriptionChannel("public", "/public", false, ["slot.available"], audience!));
        Assert.Throws<ArgumentException>(() =>
            new SubscriptionChannel("protected", "/channel/{ticket}", SubscriptionChannelAccess.Protected,
                ["slot.available"], audience!));
    }

    [Fact]
    public async Task MissingTicketIsBadRequestAndDoesNotInvokeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket?}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            calls++;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/api/channel", fixture.Token("EdDSA"), fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task HandlerStatusMappingsAndAllowedSubsetAreExact()
    {
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, _, _, _) =>
        {
            return ValueTask.FromResult(endpoint.Ticket switch
            {
                "bad" => SubscriptionRegistrationResult.BadRequest(),
                "unauthorized" => SubscriptionRegistrationResult.Unauthorized(),
                "forbidden" => SubscriptionRegistrationResult.Forbidden(),
                "not-found" => SubscriptionRegistrationResult.NotFound(),
                "conflict" => SubscriptionRegistrationResult.Conflict(),
                "widen" => SubscriptionRegistrationResult.Accepted(["other"]),
                "empty" => SubscriptionRegistrationResult.Accepted([]),
                _ => SubscriptionRegistrationResult.Accepted(["slot.available"]),
            });
        });

        foreach (var (ticket, status) in new[]
        {
            ("ok", HttpStatusCode.OK),
            ("bad", HttpStatusCode.BadRequest),
            ("unauthorized", HttpStatusCode.Unauthorized),
            ("forbidden", HttpStatusCode.Forbidden),
            ("not-found", HttpStatusCode.NotFound),
            ("conflict", HttpStatusCode.Conflict),
            ("widen", HttpStatusCode.BadRequest),
            ("empty", HttpStatusCode.BadRequest),
        })
        {
            using var response = await fixture.PostAsync(
                $"/api/channel/{ticket}", fixture.Token("EdDSA", eid: ticket), fixture.AgentKey("EdDSA"));
            Assert.Equal(status, response.StatusCode);
        }
    }

    [Fact]
    public async Task BodylessAndJsonPreferencesRemainSeparate()
    {
        SignatureUnboundRegistrationBody? received = null;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, preferences, _) =>
        {
            received = preferences;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using (var bodyless = await fixture.PostAsync(
            "/public", fixture.Token("EdDSA", eid: "bodyless"), fixture.AgentKey("EdDSA")))
        {
            Assert.Equal(HttpStatusCode.OK, bodyless.StatusCode);
            Assert.Null(received);
        }

        using (var json = await fixture.PostAsync(
            "/public", fixture.Token("EdDSA", eid: "json"), fixture.AgentKey("EdDSA"),
            """{"event_types":["other"]}"""))
        {
            Assert.Equal(HttpStatusCode.OK, json.StatusCode);
            Assert.NotNull(received);
            Assert.Equal("""{"event_types":["other"]}""", received!.GetUtf8Text());
        }
    }

    [Fact]
    public async Task DuplicateEidAndTicketOutcomesAreApplicationControlled()
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, registration, _, _) =>
        {
            if (endpoint.Ticket == "unknown")
                return ValueTask.FromResult(SubscriptionRegistrationResult.NotFound());
            if (endpoint.Ticket == "expired")
                return ValueTask.FromResult(SubscriptionRegistrationResult.NotFound("expired"));
            if (endpoint.Ticket == "reused" || !used.Add(registration.Eid))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Conflict("duplicate"));
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var unknown = await fixture.PostAsync(
            "/api/channel/unknown", fixture.Token("EdDSA", eid: "unknown"), fixture.AgentKey("EdDSA"));
        using var expired = await fixture.PostAsync(
            "/api/channel/expired", fixture.Token("EdDSA", eid: "expired"), fixture.AgentKey("EdDSA"));
        using var first = await fixture.PostAsync(
            "/api/channel/ok", fixture.Token("EdDSA", eid: "duplicate"), fixture.AgentKey("EdDSA"));
        using var duplicate = await fixture.PostAsync(
            "/api/channel/ok", fixture.Token("EdDSA", eid: "duplicate"), fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, expired.StatusCode);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public async Task CancellationPropagatesAndRegistrationServicesAreWired()
    {
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, async (_, _, _, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return SubscriptionRegistrationResult.Accepted(["slot.available"]);
        });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.PostAsync("/public", fixture.Token("EdDSA"), fixture.AgentKey("EdDSA"), cancellationToken: cancellation.Token));

        var services = new ServiceCollection();
        services.AddAAuthEventsResource(options =>
            options.KeyResolver = fixture.Resolver);
        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<SubscriptionRegistrationVerifier>());
        Assert.NotNull(provider.GetService<EventsHttpMessageVerifier>());
        Assert.NotNull(provider.GetService<EventsJwtKeyResolver>());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly IAAuthKey _apEdKey = AAuthKey.Generate();
        private readonly IAAuthKey _apEsKey = EcdsaAAuthKey.Generate();
        private readonly IAAuthKey _agentEdKey = AAuthKey.Generate();
        private readonly IAAuthKey _agentEsKey = EcdsaAAuthKey.Generate();
        private readonly string _issuer = "https://ap.example";
        private readonly string _audience = "https://resource.example";

        public Fixture(
            SubscriptionChannel channel,
            Func<SubscriptionEndpointContext, VerifiedSubscriptionRegistration,
                SignatureUnboundRegistrationBody?, CancellationToken, ValueTask<SubscriptionRegistrationResult>> handler)
        {
            var discoveryHandler = new DiscoveryHandler(_issuer, _apEdKey, _apEsKey);
            var discoveryHttp = new HttpClient(discoveryHandler);
            Resolver = new EventsJwtKeyResolver(
                new MetadataClient(discoveryHttp, clock: () => EventsTestData.Now),
                new JwksClient(discoveryHttp, minRefreshInterval: TimeSpan.Zero, clock: () => EventsTestData.Now),
                new DefaultEventsUrlPolicy(),
                new TokenVerifier { Clock = () => EventsTestData.Now, ClockSkew = TimeSpan.Zero });
            var webHost = new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(Resolver);
                    services.AddSingleton(new EventsHttpMessageVerifier
                    {
                        Clock = () => EventsTestData.Now,
                        FutureSkew = TimeSpan.Zero,
                    });
                    services.AddSingleton<SubscriptionRegistrationVerifier>();
                })
                .Configure(app => app
                    .UsePathBase("/api")
                    .UseRouting()
                    .UseEndpoints(endpoints =>
                        endpoints.MapAAuthSubscriptionRegistration(channel,
                            new DelegateHandler(handler))));
            Server = new TestServer(webHost);
            Client = Server.CreateClient();
            Client.BaseAddress = new Uri(_audience);
        }

        public EventsJwtKeyResolver Resolver { get; }
        public TestServer Server { get; }
        public HttpClient Client { get; }

        public IAAuthKey AgentKey(string algorithm) =>
            algorithm == "ES256" ? _agentEsKey : _agentEdKey;

        public string Token(
            string algorithm,
            string? audience = null,
            string? eid = null,
            DateTimeOffset? issuedAt = null,
            TimeSpan? lifetime = null)
        {
            var key = algorithm == "ES256" ? _apEsKey : _apEdKey;
            return new SubscribeTokenBuilder
            {
                Issuer = _issuer,
                Subject = "aauth:agent@ap.example",
                Audience = audience ?? _audience,
                KeyId = algorithm == "ES256" ? "ap-es" : "ap-ed",
                Key = key,
                ConfirmationKey = AgentKey(algorithm),
                IssuedAt = issuedAt ?? EventsTestData.Now,
                Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
                EventId = eid ?? "eid-1",
            }.Build().Token;
        }

        public string WrongResourceToken()
        {
            var token = Token("EdDSA");
            var parts = token.Split('.');
            var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0]))!.AsObject();
            var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1]))!.AsObject();
            payload[AAuthEventsConstants.DomainKeyClaim] = AAuthEventsConstants.ResourceDwk;
            var headerSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
            var payloadSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
            var signingInput = headerSegment + "." + payloadSegment;
            return signingInput + "." +
                Base64UrlEncoder.Encode(_apEdKey.Sign(Encoding.ASCII.GetBytes(signingInput)));
        }

        public async Task<HttpResponseMessage> PostAsync(
            string path,
            string token,
            IAAuthKey signingKey,
            string? json = null,
            CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(Client.BaseAddress!, path));
            if (json is not null)
            {
                request.Content = new StringContent(json, Encoding.UTF8, AAuthEventsConstants.JsonMediaType);
                new EventsRequestSigner(signingKey, () => token, () => EventsTestData.Now)
                    .SignRegistration(request);
            }
            else
            {
                new EventsRequestSigner(signingKey, () => token, () => EventsTestData.Now)
                    .SignBodyless(request);
            }
            return await Client.SendAsync(request, cancellationToken);
        }

        public void Dispose()
        {
            Client.Dispose();
            Server.Dispose();
        }
    }

    private sealed class DelegateHandler : IAAuthSubscriptionRegistrationHandler
    {
        private readonly Func<SubscriptionEndpointContext, VerifiedSubscriptionRegistration,
            SignatureUnboundRegistrationBody?, CancellationToken, ValueTask<SubscriptionRegistrationResult>> _handler;

        public DelegateHandler(Func<SubscriptionEndpointContext, VerifiedSubscriptionRegistration,
            SignatureUnboundRegistrationBody?, CancellationToken, ValueTask<SubscriptionRegistrationResult>> handler) =>
            _handler = handler;

        public ValueTask<SubscriptionRegistrationResult> RegisterAsync(
            SubscriptionEndpointContext endpoint,
            VerifiedSubscriptionRegistration registration,
            SignatureUnboundRegistrationBody? preferences,
            CancellationToken cancellationToken = default) =>
            _handler(endpoint, registration, preferences, cancellationToken);
    }

    private sealed class DiscoveryHandler : HttpMessageHandler
    {
        private readonly string _issuer;
        private readonly IAAuthKey _edKey;
        private readonly IAAuthKey _esKey;

        public DiscoveryHandler(string issuer, IAAuthKey edKey, IAAuthKey esKey)
        {
            _issuer = issuer;
            _edKey = edKey;
            _esKey = esKey;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var uri = request.RequestUri!.ToString();
            if (uri == $"{_issuer}/.well-known/aauth-agent.json")
                return Task.FromResult(Json(new JsonObject
                {
                    ["issuer"] = _issuer,
                    ["jwks_uri"] = $"{_issuer}/jwks",
                }));
            if (uri == $"{_issuer}/jwks")
                return Task.FromResult(Json(new JsonObject
                {
                    ["keys"] = new JsonArray(Jwk("ap-ed", _edKey), Jwk("ap-es", _esKey)),
                }));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static JsonObject Jwk(string kid, IAAuthKey key)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = key.Algorithm;
            return jwk;
        }

        private static HttpResponseMessage Json(JsonObject body) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
    }
}
