using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
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

namespace AAuth.Events.Tests.Conformance;

public sealed class RegistrationConformanceTests
{
    private const string ResourceAudience = "https://resource.example";

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task PublicRegistrationUsesBodylessAndRegistrationJsonProfiles(string algorithm)
    {
        SignatureUnboundRegistrationBody? preferences = null;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available", "slot.cancelled"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, body, _) =>
        {
            preferences = body;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using (var bodyless = await fixture.PostAsync(
            "/public", fixture.Token(algorithm, eid: "bodyless"), fixture.AgentKey(algorithm)))
        {
            Assert.Equal(HttpStatusCode.OK, bodyless.StatusCode);
            Assert.Null(preferences);
        }

        const string json = """{"event_types":["slot.cancelled"]}""";
        using (var registration = await fixture.PostAsync(
            "/public", fixture.Token(algorithm, eid: "json"), fixture.AgentKey(algorithm), json))
        {
            Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
            Assert.NotNull(preferences);
            Assert.Equal(json, preferences!.GetUtf8Text());
            Assert.Equal("application/json", preferences.ContentType.Split(';', 2)[0]);
        }
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task RegistrationCarriesIssuerSubjectAudienceEidAndTimes(string algorithm)
    {
        VerifiedSubscriptionRegistration? received = null;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, registration, _, _) =>
        {
            received = registration;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });
        var issuedAt = EventsTestData.Now.AddSeconds(-2);

        using var response = await fixture.PostAsync(
            "/public",
            fixture.Token(
                algorithm,
                eid: "eid-claims",
                issuedAt: issuedAt,
                lifetime: TimeSpan.FromMinutes(5),
                subject: "aauth:agent@ap.example"),
            fixture.AgentKey(algorithm));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(received);
        Assert.Equal("https://ap.example", received!.Issuer);
        Assert.Equal("aauth:agent@ap.example", received.AgentSubject);
        Assert.Equal("https://resource.example", received.ResourceAudience);
        Assert.Equal("eid-claims", received.Eid);
        Assert.Equal(issuedAt.ToUnixTimeSeconds(), received.IssuedAt.ToUnixTimeSeconds());
        Assert.Equal(issuedAt.AddMinutes(5).ToUnixTimeSeconds(), received.ExpiresAt.ToUnixTimeSeconds());
        Assert.Equal(algorithm, received.ApSigningKey.Algorithm);
        Assert.Equal(algorithm, received.HttpSignatureKey.Algorithm);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task SubscribeTokenIsTheSoleCredentialAndForbiddenHeadersAreRejected()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var request = fixture.CreateRequest(
            "/public", fixture.Token("EdDSA"), fixture.AgentKey("EdDSA"));
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer not-an-events-credential");

        using var response = await fixture.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task ProtectedRegistrationBindsPathBaseAndEscapedOpaqueTicket()
    {
        string? ticket = null;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, _, _, _) =>
        {
            ticket = endpoint.Ticket;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/api/channel/ticket%2Dencoded",
            fixture.Token("EdDSA", eid: "path-bound"),
            fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ticket-encoded", ticket);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task ProtectedRegistrationRejectsSignaturePathSubstitutionBeforeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var request = fixture.CreateRequest(
            "/api/channel/expected",
            fixture.Token("EdDSA", eid: "path-substitution"),
            fixture.AgentKey("EdDSA"));
        request.RequestUri = new Uri(fixture.BaseAddress, "/api/channel/other");

        using var response = await fixture.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("unknown", 404)]
    [InlineData("expired", 404)]
    [InlineData("reused", 409)]
    [InlineData("wrong-context", 404)]
    [InlineData("wrong-agent", 403)]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task ProtectedTicketOutcomesAreResourceControlled(string ticket, int expectedStatus)
    {
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, registration, _, _) =>
        {
            var status = endpoint.Ticket switch
            {
                "unknown" => SubscriptionRegistrationResult.NotFound("unknown ticket"),
                "expired" => SubscriptionRegistrationResult.NotFound("ticket expired"),
                "reused" => SubscriptionRegistrationResult.Conflict("ticket already used"),
                "wrong-context" => SubscriptionRegistrationResult.NotFound("wrong resource context"),
                "wrong-agent" when registration.AgentSubject != "aauth:agent@ap.example"
                    => SubscriptionRegistrationResult.Forbidden("ticket belongs to another agent"),
                "wrong-agent" => SubscriptionRegistrationResult.Forbidden("ticket is not bound"),
                _ => SubscriptionRegistrationResult.Accepted(["slot.available"]),
            };
            return ValueTask.FromResult(status);
        });

        using var response = await fixture.PostAsync(
            $"/channel/{ticket}",
            fixture.Token(
                "EdDSA",
                eid: ticket,
                subject: ticket == "wrong-agent"
                    ? "aauth:other@ap.example"
                    : "aauth:agent@ap.example"),
            fixture.AgentKey("EdDSA"));

        Assert.Equal((HttpStatusCode)expectedStatus, response.StatusCode);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task ProtectedTicketIsBoundToTheSubscribeTokenAgent()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (endpoint, registration, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(
                endpoint.Ticket == "agent-ticket" &&
                registration.AgentSubject == "aauth:agent@ap.example"
                    ? SubscriptionRegistrationResult.Accepted(["slot.available"])
                    : SubscriptionRegistrationResult.Forbidden("agent binding failed"));
        });

        using var wrongAgent = await fixture.PostAsync(
            "/channel/agent-ticket",
            fixture.Token("EdDSA", subject: "aauth:other@ap.example"),
            fixture.AgentKey("EdDSA"));
        using var correctAgent = await fixture.PostAsync(
            "/channel/agent-ticket",
            fixture.Token("EdDSA", eid: "agent-ticket"),
            fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.Forbidden, wrongAgent.StatusCode);
        Assert.Equal(HttpStatusCode.OK, correctAgent.StatusCode);
        Assert.Equal(2, calls);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task CnfMustMatchTheAgentHttpSignatureKey()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA"),
            fixture.DifferentAgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("wrong-audience", "https://other.example", 403)]
    [InlineData("expired", "https://resource.example", 401)]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task InvalidAudienceAndExpiredTimesMapWithoutHandlerInvocation(
        string kind, string audience, int expectedStatus)
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available"], "https://resource.example");
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        var issuedAt = kind == "expired"
            ? EventsTestData.Now.AddMinutes(-10)
            : EventsTestData.Now;
        var lifetime = kind == "expired" ? TimeSpan.FromMinutes(1) : TimeSpan.FromMinutes(5);
        using var response = await fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA", audience: audience, issuedAt: issuedAt, lifetime: lifetime),
            fixture.AgentKey("EdDSA"));

        Assert.Equal((HttpStatusCode)expectedStatus, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task MissingOrUnknownJwtKeyAndEidAreUnauthorizedOrMalformed()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var unknownKey = await fixture.PostAsync(
            "/public",
            fixture.RewriteToken(fixture.Token("EdDSA"), (header, _) => header["kid"] = "unknown"),
            fixture.AgentKey("EdDSA"));
        using var missingEid = await fixture.PostAsync(
            "/public",
            fixture.RewriteToken(fixture.Token("EdDSA"), (_, payload) => payload.Remove(AAuthEventsConstants.EventIdClaim)),
            fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.Unauthorized, unknownKey.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, missingEid.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C12")]
    [Trait("Spec", "RF3")]
    public async Task DuplicateEidIsRejectedWithConflict()
    {
        var seen = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, registration, _, _) =>
        {
            return ValueTask.FromResult(
                seen.TryAdd(registration.Eid, 0)
                    ? SubscriptionRegistrationResult.Accepted(["slot.available"])
                    : SubscriptionRegistrationResult.Conflict("eid already registered"));
        });

        using var first = await fixture.PostAsync(
            "/public", fixture.Token("EdDSA", eid: "duplicate"), fixture.AgentKey("EdDSA"));
        using var duplicate = await fixture.PostAsync(
            "/public", fixture.Token("EdDSA", eid: "duplicate"), fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C12")]
    [Trait("Spec", "RF3")]
    public async Task ConcurrentRegistrationsConsumeAnEidAtomically()
    {
        var seen = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, registration, _, _) =>
        {
            var result = seen.TryAdd(registration.Eid, 0)
                ? SubscriptionRegistrationResult.Accepted(["slot.available"])
                : SubscriptionRegistrationResult.Conflict("eid already registered");
            return ValueTask.FromResult(result);
        });
        var token = fixture.Token("EdDSA", eid: "concurrent");

        var responses = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(_ =>
                fixture.PostAsync("/public", token, fixture.AgentKey("EdDSA"))));

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(7, responses.Count(response => response.StatusCode == HttpStatusCode.Conflict));
        foreach (var response in responses) response.Dispose();
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C12")]
    public async Task SelectedEventSubsetIsAcceptedButWideningIsRejected()
    {
        var channel = SubscriptionChannel.Public(
            "public", "/public", ["slot.available", "slot.cancelled"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, preferences, _) =>
        {
            var requested = preferences is null
                ? ["slot.available"]
                : JsonNode.Parse(preferences.GetUtf8Text())!["event_types"]!
                    .AsArray().Select(value => value!.GetValue<string>()).ToArray();
            return ValueTask.FromResult(
                requested.Contains("other", StringComparer.Ordinal)
                    ? SubscriptionRegistrationResult.Accepted(["slot.available", "other"])
                    : SubscriptionRegistrationResult.Accepted(requested));
        });

        using var subset = await fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA", eid: "subset"),
            fixture.AgentKey("EdDSA"),
            """{"event_types":["slot.available"]}""");
        using var widen = await fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA", eid: "widen"),
            fixture.AgentKey("EdDSA"),
            """{"event_types":["other"]}""");

        Assert.Equal(HttpStatusCode.OK, subset.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, widen.StatusCode);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C12")]
    public async Task RegistrationBodyIsSignatureUnboundButContentTypeRemainsBound()
    {
        SignatureUnboundRegistrationBody? received = null;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, preferences, _) =>
        {
            received = preferences;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });
        using var request = fixture.CreateRequest(
            "/public",
            fixture.Token("EdDSA", eid: "unbound-body"),
            fixture.AgentKey("EdDSA"),
            """{"event_types":["signed"]}""");
        request.Content = new StringContent(
            """{"event_types":["substituted"]}""", Encoding.UTF8, AAuthEventsConstants.JsonMediaType);

        using var response = await fixture.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(received);
        Assert.Equal("""{"event_types":["substituted"]}""", received!.GetUtf8Text());
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task BodylessProfileRejectsARequestBody()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });
        using var request = fixture.CreateRequest(
            "/public", fixture.Token("EdDSA"), fixture.AgentKey("EdDSA"));
        request.Content = new StringContent("{}", Encoding.UTF8, AAuthEventsConstants.JsonMediaType);

        using var response = await fixture.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(
        "sig=(\"@method\" \"@authority\" \"signature-key\" \"@path\");created=1750000000")]
    [InlineData(
        "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-type\" \"content-type\");created=1750000000")]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C5")]
    public async Task RegistrationRequiresTheExactHttpSignatureComponentSequence(string signatureInput)
    {
        var calls = 0;
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });
        using var request = fixture.CreateRequest(
            "/public",
            fixture.Token("EdDSA", eid: "profile"),
            fixture.AgentKey("EdDSA"),
            "{}");
        request.Headers.Remove("Signature-Input");
        request.Headers.TryAddWithoutValidation("Signature-Input", signatureInput);

        using var response = await fixture.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task HandlerResultsMapToTheRegistrationStatusCodes()
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
                _ => SubscriptionRegistrationResult.Accepted(["slot.available"]),
            });
        });

        foreach (var (ticket, expected) in new[]
        {
            ("ok", HttpStatusCode.OK),
            ("bad", HttpStatusCode.BadRequest),
            ("unauthorized", HttpStatusCode.Unauthorized),
            ("forbidden", HttpStatusCode.Forbidden),
            ("not-found", HttpStatusCode.NotFound),
            ("conflict", HttpStatusCode.Conflict),
        })
        {
            using var response = await fixture.PostAsync(
                $"/channel/{ticket}",
                fixture.Token("EdDSA", eid: ticket),
                fixture.AgentKey("EdDSA"));
            Assert.Equal(expected, response.StatusCode);
        }
    }

    [Fact]
    [Trait("Spec", "L247-L339")]
    [Trait("Spec", "C8")]
    public async Task MissingProtectedTicketIsBadRequestAndDoesNotInvokeHandler()
    {
        var calls = 0;
        var channel = SubscriptionChannel.Protected(
            "protected", "/channel/{ticket?}", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, (_, _, _, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted(["slot.available"]));
        });

        using var response = await fixture.PostAsync(
            "/channel",
            fixture.Token("EdDSA"),
            fixture.AgentKey("EdDSA"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, calls);
    }

    [Fact]
    [Trait("Spec", "L588-L599")]
    [Trait("Spec", "RF3")]
    public async Task CancellationIsPropagatedToTheRegistrationHandler()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var channel = SubscriptionChannel.Public("public", "/public", ["slot.available"], ResourceAudience);
        using var fixture = new Fixture(channel, async (_, _, _, cancellationToken) =>
        {
            entered.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return SubscriptionRegistrationResult.Accepted(["slot.available"]);
        });
        using var cancellation = new CancellationTokenSource();
        var sending = fixture.PostAsync(
            "/public",
            fixture.Token("EdDSA", eid: "cancelled"),
            fixture.AgentKey("EdDSA"),
            cancellationToken: cancellation.Token);
        await entered.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly IAAuthKey _apEdKey = AAuthKey.Generate();
        private readonly IAAuthKey _apEsKey = EcdsaAAuthKey.Generate();
        private readonly IAAuthKey _agentEdKey = AAuthKey.Generate();
        private readonly IAAuthKey _agentEsKey = EcdsaAAuthKey.Generate();
        private readonly IAAuthKey _differentEdKey = AAuthKey.Generate();
        private readonly IAAuthKey _differentEsKey = EcdsaAAuthKey.Generate();
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
                        endpoints.MapAAuthSubscriptionRegistration(channel, new DelegateHandler(handler))));
            Server = new TestServer(webHost);
            Client = Server.CreateClient();
            Client.BaseAddress = new Uri(_audience);
        }

        public EventsJwtKeyResolver Resolver { get; }
        public TestServer Server { get; }
        public HttpClient Client { get; }
        public Uri BaseAddress => Client.BaseAddress!;

        public IAAuthKey AgentKey(string algorithm) =>
            algorithm == "ES256" ? _agentEsKey : _agentEdKey;

        public IAAuthKey DifferentAgentKey(string algorithm) =>
            algorithm == "ES256" ? _differentEsKey : _differentEdKey;

        public string Token(
            string algorithm,
            string? audience = null,
            string? eid = null,
            DateTimeOffset? issuedAt = null,
            TimeSpan? lifetime = null,
            string subject = "aauth:agent@ap.example")
        {
            var key = algorithm == "ES256" ? _apEsKey : _apEdKey;
            return new SubscribeTokenBuilder
            {
                Issuer = _issuer,
                Subject = subject,
                Audience = audience ?? _audience,
                KeyId = algorithm == "ES256" ? "ap-es" : "ap-ed",
                Key = key,
                ConfirmationKey = AgentKey(algorithm),
                IssuedAt = issuedAt ?? EventsTestData.Now,
                Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
                EventId = eid ?? "eid-1",
            }.Build().Token;
        }

        public string RewriteToken(
            string token,
            Action<JsonObject, JsonObject> rewrite)
        {
            var parts = token.Split('.');
            var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0]))!.AsObject();
            var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1]))!.AsObject();
            rewrite(header, payload);
            var headerSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
            var payloadSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
            var signingInput = headerSegment + "." + payloadSegment;
            var key = header["kid"]?.GetValue<string>() == "ap-es" ? _apEsKey : _apEdKey;
            return signingInput + "." +
                Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(signingInput)));
        }

        public HttpRequestMessage CreateRequest(
            string path,
            string token,
            IAAuthKey signingKey,
            string? json = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseAddress, path));
            if (json is not null)
            {
                request.Content = new StringContent(
                    json, Encoding.UTF8, AAuthEventsConstants.JsonMediaType);
                new EventsRequestSigner(
                    signingKey, () => token, () => EventsTestData.Now).SignRegistration(request);
            }
            else
            {
                new EventsRequestSigner(
                    signingKey, () => token, () => EventsTestData.Now).SignBodyless(request);
            }
            return request;
        }

        public Task<HttpResponseMessage> PostAsync(
            string path,
            string token,
            IAAuthKey signingKey,
            string? json = null,
            CancellationToken cancellationToken = default)
        {
            var request = CreateRequest(path, token, signingKey, json);
            return SendAndDisposeRequestAsync(request, cancellationToken);
        }

        public Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken = default) =>
            Client.SendAsync(request, cancellationToken);

        private async Task<HttpResponseMessage> SendAndDisposeRequestAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                return await Client.SendAsync(request, cancellationToken);
            }
            finally
            {
                request.Dispose();
            }
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

        public DelegateHandler(
            Func<SubscriptionEndpointContext, VerifiedSubscriptionRegistration,
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
                Content = new StringContent(
                    body.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
    }
}
