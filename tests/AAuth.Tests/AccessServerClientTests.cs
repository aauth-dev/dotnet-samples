using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests;

/// <summary>
/// Unit tests for <see cref="AccessServerClient"/> — the Person Server's
/// signed PS-to-AS federation client. A stub <see cref="HttpMessageHandler"/>
/// stands in for the Access Server: it serves the AS metadata + JWKS and a
/// configurable <c>POST /token</c> response, so each test drives one branch of
/// the client (success, payment-required, claims, delivery-verification
/// failure) without booting a server.
/// </summary>
public class AccessServerClientTests
{
    private const string AsIssuer = "https://as.test";
    private const string PsIssuer = "https://ps.test";
    private const string ResourceUrl = "https://whoami.test";
    private const string Subject = "pairwise-sub";
    private const string AsKid = "as-1";

    private static readonly AAuthKey AsKey = AAuthKey.Generate();

    [Fact]
    public async Task UnstructuredErrorsDoNotEnterExceptionDiagnostics()
    {
        const string sentinel = "TOKEN-SECRET-SENTINEL person-sentinel@example.test\nforged-log-line";
        var stub = new StubAccessServer(() => new(HttpStatusCode.BadGateway)
        {
            Content = new StringContent(sentinel), ReasonPhrase = "TOKEN-SECRET-SENTINEL",
        });
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => BuildClient(stub).FederateAsync(AsIssuer, NewRequest(AAuthKey.Generate())));
        Assert.DoesNotContain("SENTINEL", error.ToString());
        Assert.DoesNotContain("person-sentinel", error.ToString());
        Assert.DoesNotContain("forged-log-line", error.ToString());
        Assert.Equal(HttpStatusCode.BadGateway, error.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FederateAsync_DispatchesMixedClarificationAndNewInteractions(bool claimsFirst)
    {
        var agentKey = AAuthKey.Generate();
        var token = await BuildAuthTokenAsync(agentKey, ResourceUrl, "whoami");
        var callbacks = new List<string>();
        var polls = 0;
        HttpResponseMessage Pending(string requirement, string code = "ABCDEFGH")
        {
            var response = new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Content = JsonContent.Create(new { clarification = "Why?", timeout = 30, required_claims = new[] { "email" } }),
            };
            response.Headers.Location = new Uri($"{AsIssuer}/pending/mixed");
            response.Headers.TryAddWithoutValidation("Retry-After", "0");
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=" + requirement
                + (requirement == "interaction" ? $"; url=\"{AsIssuer}/login\"; code=\"{code}\"" : ""));
            return response;
        }
        var stub = new StubAccessServer(
            () => Pending(claimsFirst ? "claims" : "clarification"),
            body => body?["action"] is null ? Pending("clarification") : new(HttpStatusCode.NoContent),
            () => ++polls switch
            {
                1 => Pending("interaction"),
                2 => Pending("interaction"),
                3 => Pending("interaction", "12345678"),
                _ => Ok(token),
            });
        var result = await BuildClient(stub).FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "resource", AgentToken = "agent", AgentKey = agentKey,
            AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
            ExpectedAudience = ResourceUrl, ExpectedSubject = Subject, ExpectedPersonServer = PsIssuer, RequestedScope = "whoami",
            PresentedToken = "presented", PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
            OnClaimsRequired = (_, _) => { callbacks.Add("claims"); return Task.FromResult(new ClaimsResponse()); },
            OnClarificationRequired = (_, _) => { callbacks.Add("clarification"); return Task.FromResult(ClarificationResponse.Respond("because")); },
            OnInteractionRequired = (interaction, _) => { callbacks.Add(interaction.Code!); return Task.CompletedTask; },
        });
        Assert.Equal(token, result);
        Assert.Equal(claimsFirst ? new[] { "claims", "clarification", "ABCDEFGH", "12345678" }
            : new[] { "clarification", "ABCDEFGH", "12345678" }, callbacks);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FederateAsync_RejectsOverlongAuthToken_DirectOrDeferred(bool deferred)
    {
        var agentKey = AAuthKey.Generate();
        var token = await BuildAuthTokenAsync(agentKey, ResourceUrl, "whoami");
        HttpResponseMessage Pending()
        {
            var response = new HttpResponseMessage(HttpStatusCode.Accepted) { Content = JsonContent.Create(new { status = "pending" }) };
            response.Headers.Location = new Uri($"{AsIssuer}/pending/expiry");
            response.Headers.TryAddWithoutValidation("Retry-After", "0");
            return response;
        }
        var stub = new StubAccessServer(() => deferred ? Pending() : Ok(token), pendingGetResponse: () => Ok(token));
        await Assert.ThrowsAsync<TokenVerificationException>(() => BuildClient(stub).FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "resource", AgentToken = "agent", AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            ExpectedAudience = ResourceUrl, ExpectedSubject = Subject, ExpectedPersonServer = PsIssuer, AgentKey = agentKey,
            PresentedToken = "presented", PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
            OnInteractionRequired = (_, _) => Task.CompletedTask,
        }));
    }

    [Fact]
    public async Task FederateAsync_ForwardsChildToken()
    {
        var key = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(key, ResourceUrl, "whoami");
        var stub = new StubAccessServer(() => Ok(authToken));
        await BuildClient(stub).FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "resource", AgentToken = "parent", SubagentToken = "child",
            AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
            ExpectedAudience = ResourceUrl, ExpectedSubject = Subject, ExpectedPersonServer = PsIssuer, AgentKey = key,
            PresentedToken = "presented", PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
        });
        Assert.Equal("child", (string?)stub.LastTokenRequestBody!["subagent_token"]);
        Assert.Equal("presented", (string?)stub.LastTokenRequestBody["presented_token"]);
    }

    [Fact]
    public async Task FederateAsync_RejectsReservedClaimRequestBeforeCallback()
    {
        var stub = new StubAccessServer(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Content = JsonContent.Create(new { required_claims = new[] { "sub" } }),
            };
            response.Headers.Location = new Uri($"{AsIssuer}/pending/claims");
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=claims");
            return response;
        });
        var called = false;
        await Assert.ThrowsAsync<TokenVerificationException>(() => BuildClient(stub).FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "resource", AgentToken = "agent", AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            ExpectedAudience = ResourceUrl, ExpectedSubject = Subject, ExpectedPersonServer = PsIssuer, AgentKey = AAuthKey.Generate(),
            PresentedToken = "presented", PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(2),
            OnClaimsRequired = (_, _) => { called = true; return Task.FromResult(new ClaimsResponse()); },
        }));
        Assert.False(called);
        Assert.Null(stub.LastClaimsPushBody);
    }

    [Fact]
    public async Task FederateAsync_ReturnsVerifiedAuthToken_OnSuccess()
    {
        var agentKey = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(agentKey, audience: ResourceUrl, scope: "whoami");
        var stub = new StubAccessServer(() => Ok(authToken));
        var client = BuildClient(stub);

        var result = await client.FederateAsync(AsIssuer, NewRequest(agentKey));

        Assert.Equal(authToken, result);
        // The signed POST carried both tokens to the AS token endpoint.
        Assert.NotNull(stub.LastTokenRequestBody);
        Assert.Equal("the-resource-token", (string?)stub.LastTokenRequestBody!["resource_token"]);
        Assert.Equal("the-agent-token", (string?)stub.LastTokenRequestBody["agent_token"]);
    }

    [Fact]
    public async Task FederateAsync_IncludesUpstreamToken_WhenProvided()
    {
        var agentKey = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(agentKey, audience: ResourceUrl, scope: "whoami");
        var stub = new StubAccessServer(() => Ok(authToken));
        var client = BuildClient(stub);

        await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            UpstreamToken = "the-upstream-token",
            ExpectedAudience = ResourceUrl,
            ExpectedSubject = Subject,
            ExpectedPersonServer = PsIssuer,
            PresentedToken = "the-presented-token",
            PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AgentKey = agentKey,
            RequestedScope = "whoami",
        });

        Assert.Equal("the-upstream-token", (string?)stub.LastTokenRequestBody!["upstream_token"]);
    }

    [Fact]
    public async Task FederateAsync_SettlesPaymentThenComposesClaims_On402()
    {
        var agentKey = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(agentKey, audience: ResourceUrl, scope: "whoami");
        AAuthPaymentSettlementContext? paymentSeen = null;
        var stub = new StubAccessServer(
            tokenResponse: () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired)
                {
                    Content = JsonContent.Create(new { invoice = "42" }),
                };
                response.Headers.Location = new Uri($"{AsIssuer}/pending/pay");
                response.Headers.TryAddWithoutValidation("WWW-Authenticate", "Payment method=\"stripe\"");
                return response;
            },
            claimsResponse: _ => Ok(authToken),
            pendingGetResponse: () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Accepted)
                {
                    Content = JsonContent.Create(new { status = "pending", required_claims = new[] { "email" } }),
                };
                response.Headers.Location = new Uri($"{AsIssuer}/pending/pay");
                response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=claims");
                return response;
            });
        var client = BuildClient(stub);

        var request = NewRequest(agentKey);
        request = new AccessServerRequest
        {
            AuthorizationExpiresAt = request.AuthorizationExpiresAt,
            ResourceToken = request.ResourceToken,
            AgentToken = request.AgentToken,
            ExpectedAudience = request.ExpectedAudience,
            ExpectedSubject = request.ExpectedSubject,
            ExpectedPersonServer = request.ExpectedPersonServer,
            PresentedToken = request.PresentedToken,
            PresentedTokenExpiresAt = request.PresentedTokenExpiresAt,
            AgentKey = request.AgentKey,
            RequestedScope = request.RequestedScope,
            OnPaymentRequired = (payment, _) =>
            {
                paymentSeen = payment;
                return Task.FromResult(AAuthPaymentSettlementResult.Success);
            },
            OnClaimsRequired = (_, _) => Task.FromResult(new ClaimsResponse
            {
                Claims = new Dictionary<string, JsonNode?> { ["email"] = "demo@person.example" },
            }),
        };
        var result = await client.FederateAsync(AsIssuer, request);

        Assert.Equal(authToken, result);
        Assert.NotNull(paymentSeen);
        Assert.Equal($"{AsIssuer}/pending/pay", paymentSeen!.PendingUrl.ToString());
        Assert.Equal(AsIssuer, paymentSeen.AccessServerOrigin);
        Assert.Equal("Payment", paymentSeen.Challenge.Scheme);
        Assert.Equal("demo@person.example", (string?)stub.LastClaimsPushBody!["email"]);
        Assert.False(stub.LastClaimsPushBody.ContainsKey("sub"));
    }

    [Fact]
    public async Task FederateAsync_DeniesPayment_WhenSettlementUnavailable()
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
            response.Headers.Location = new Uri($"{AsIssuer}/pending/pay");
            response.Headers.TryAddWithoutValidation("WWW-Authenticate", "Payment method=\"stripe\"");
            return response;
        });

        var request = NewRequest(agentKey);
        request = new AccessServerRequest
        {
            AuthorizationExpiresAt = request.AuthorizationExpiresAt,
            ResourceToken = request.ResourceToken,
            AgentToken = request.AgentToken,
            ExpectedAudience = request.ExpectedAudience,
            ExpectedSubject = request.ExpectedSubject,
            ExpectedPersonServer = request.ExpectedPersonServer,
            PresentedToken = request.PresentedToken,
            PresentedTokenExpiresAt = request.PresentedTokenExpiresAt,
            AgentKey = request.AgentKey,
            RequestedScope = request.RequestedScope,
            OnPaymentRequired = (_, _) => Task.FromResult(AAuthPaymentSettlementResult.Declined),
        };
        var ex = await Assert.ThrowsAsync<AAuthTokenExchangeException>(
            () => BuildClient(stub).FederateAsync(AsIssuer, request));

        Assert.Equal("denied", ex.ErrorCode);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal("payment settlement is unavailable", ex.Detail);
    }

    [Fact]
    public async Task FederateAsync_ThrowsNotSupported_OnClaimsRequirement_WhenNoHandler()
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Accepted);
            response.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name, "requirement=claims; claims=\"email\"");
            response.Headers.Location = new Uri($"{AsIssuer}/claims/abc");
            return response;
        });
        var client = BuildClient(stub);

        // No OnClaimsRequired handler configured -> NotSupportedException.
        var ex = await Assert.ThrowsAsync<NotSupportedException>(
            () => client.FederateAsync(AsIssuer, NewRequest(agentKey)));

        Assert.Contains("requirement=claims", ex.Message);
    }

    [Fact]
    public async Task FederateAsync_PushesClaimsAndReturnsAuthToken_OnClaimsRequirement()
    {
        var agentKey = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(agentKey, audience: ResourceUrl, scope: "whoami");

        // First /token call -> 202 requirement=claims (required_claims in body);
        // the signed claims push -> 200 auth_token.
        var stub = new StubAccessServer(
            tokenResponse: () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Accepted)
                {
                    Content = new StringContent(
                        new JsonObject
                        {
                            ["status"] = "pending",
                            ["required_claims"] = new JsonArray("email", "tenant"),
                        }.ToJsonString(),
                        Encoding.UTF8,
                        "application/json"),
                };
                response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=claims");
                response.Headers.Location = new Uri($"{AsIssuer}/pending/abc");
                return response;
            },
            claimsResponse: _ => Ok(authToken));
        var client = BuildClient(stub);

        ClaimsRequirement? seen = null;
        var result = await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            ExpectedAudience = ResourceUrl,
            ExpectedSubject = Subject,
            ExpectedPersonServer = PsIssuer,
            PresentedToken = "the-presented-token",
            PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AgentKey = agentKey,
            RequestedScope = "whoami",
            OnClaimsRequired = (requirement, _) =>
            {
                seen = requirement;
                return Task.FromResult(new ClaimsResponse
                {
                    Claims = new Dictionary<string, JsonNode?>
                    {
                        ["email"] = "demo@person.example",
                        ["tenant"] = "demo-tenant",
                    },
                });
            },
        });

        Assert.Equal(authToken, result);
        Assert.NotNull(seen);
        Assert.Contains("email", seen!.RequiredClaims);
        Assert.Contains("tenant", seen.RequiredClaims);
        // The claims were POSTed (signed) to the pending URL, never a `sub`.
        Assert.NotNull(stub.LastClaimsPushBody);
        Assert.False(stub.LastClaimsPushBody!.ContainsKey("sub"));
        Assert.Equal("demo@person.example", (string?)stub.LastClaimsPushBody["email"]);
    }

    [Fact]
    public async Task FederateAsync_ComposesInteractionThenClaims_OnSameLocation()
    {
        // Spec §Trust Establishment: mechanisms compose onto one Location.
        // POST /token -> 202 requirement=interaction; the deferred poll then
        // escalates to 202 requirement=claims on the SAME Location; the signed
        // claims push -> 200 auth_token. Verifies the client handles a
        // requirement=claims that arrives MID-POLL, not just as the first reply.
        var agentKey = AAuthKey.Generate();
        var authToken = await BuildAuthTokenAsync(agentKey, audience: ResourceUrl, scope: "whoami");

        var stub = new StubAccessServer(
            tokenResponse: () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Accepted);
                response.Headers.TryAddWithoutValidation(
                    AAuthRequirementHeader.Name, "requirement=interaction; code=\"abc123\"; url=\"https://as.test/login\"");
                response.Headers.Location = new Uri($"{AsIssuer}/pending/xyz");
                return response;
            },
            claimsResponse: _ => Ok(authToken),
            pendingGetResponse: () =>
            {
                // The interaction completed; the AS now needs identity claims.
                var response = new HttpResponseMessage(HttpStatusCode.Accepted)
                {
                    Content = new StringContent(
                        new JsonObject { ["required_claims"] = new JsonArray("email") }.ToJsonString(),
                        Encoding.UTF8,
                        "application/json"),
                };
                response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=claims");
                response.Headers.Location = new Uri($"{AsIssuer}/pending/xyz");
                return response;
            });
        var client = BuildClient(stub);

        var interactionSeen = false;
        ClaimsRequirement? claimsSeen = null;
        var result = await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            ExpectedAudience = ResourceUrl,
            ExpectedSubject = Subject,
            ExpectedPersonServer = PsIssuer,
            PresentedToken = "the-presented-token",
            PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AgentKey = agentKey,
            RequestedScope = "whoami",
            OnInteractionRequired = (_, _) => { interactionSeen = true; return Task.CompletedTask; },
            OnClaimsRequired = (requirement, _) =>
            {
                claimsSeen = requirement;
                return Task.FromResult(new ClaimsResponse
                {
                    Claims = new Dictionary<string, JsonNode?>
                    {
                        ["email"] = "demo@person.example",
                    },
                });
            },
        });

        Assert.Equal(authToken, result);
        Assert.True(interactionSeen, "interaction callback should have fired first");
        Assert.NotNull(claimsSeen);
        Assert.Contains("email", claimsSeen!.RequiredClaims);
        Assert.Equal("demo@person.example", (string?)stub.LastClaimsPushBody!["email"]);
    }
    [Fact]
    public async Task FederateAsync_ThrowsVerification_WhenAudienceMismatch()
    {
        var agentKey = AAuthKey.Generate();
        // The AS mints a token for a DIFFERENT resource than the PS expects.
        var authToken = await BuildAuthTokenAsync(agentKey, audience: "https://evil.test", scope: "whoami");
        var stub = new StubAccessServer(() => Ok(authToken));
        var client = BuildClient(stub);

        var ex = await Assert.ThrowsAsync<TokenVerificationException>(
            () => client.FederateAsync(AsIssuer, NewRequest(agentKey)));

        Assert.Contains("delivery verification failed", ex.Message);
    }

    [Fact]
    public async Task FederateAsync_ThrowsTokenExchange_OnStructuredError()
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(
                new JsonObject
                {
                    ["error"] = "invalid_resource_token",
                    ["detail"] = "aud mismatch",
                    ["type"] = "https://example.test/server_error",
                }.ToJsonString(),
                Encoding.UTF8,
                "application/problem+json"),
        });
        var client = BuildClient(stub);

        var ex = await Assert.ThrowsAsync<AAuthTokenExchangeException>(
            () => client.FederateAsync(AsIssuer, NewRequest(agentKey)));

        Assert.Equal("invalid_resource_token", ex.ErrorCode);
        Assert.Equal("aud mismatch", ex.Detail);
        Assert.True(ex.IsTerminal);
        Assert.Equal(400, ex.StatusCode);
    }

    [Theory]
    [InlineData("{\"error\":\"server_error\",\"error_description\":\"legacy\"}")]
    [InlineData("{\"error\":\"server_error\",\"detail\":123,\"type\":\"denied\"}")]
    public async Task FederateAsync_OnlyUsesStringDetail(string body)
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/problem+json"),
        });
        var error = await Assert.ThrowsAsync<AAuthTokenExchangeException>(
            () => BuildClient(stub).FederateAsync(AsIssuer, NewRequest(agentKey)));
        Assert.Equal("server_error", error.ErrorCode);
        Assert.False(error.IsTerminal);
        Assert.Null(error.Detail);
    }

    [Theory]
    [InlineData("{\"type\":\"denied\",\"detail\":\"no error\"}")]
    [InlineData("{\"error\":42}")]
    [InlineData("{\"error\":{}}")]
    [InlineData("{\"error\":\"\"}")]
    public async Task FederateAsync_InvalidErrorMember_FallsBack(string body)
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/problem+json"),
        });
        await Assert.ThrowsAsync<HttpRequestException>(
            () => BuildClient(stub).FederateAsync(AsIssuer, NewRequest(agentKey)));
    }

    // -- helpers ---------------------------------------------------------

    private static AccessServerRequest NewRequest(AAuthKey agentKey) => new()
    {
        AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        ResourceToken = "the-resource-token",
        AgentToken = "the-agent-token",
        ExpectedAudience = ResourceUrl,
        ExpectedSubject = Subject,
        ExpectedPersonServer = PsIssuer,
        PresentedToken = "the-presented-token",
        PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        AgentKey = agentKey,
        RequestedScope = "whoami",
    };

    private static AccessServerClient BuildClient(StubAccessServer stub)
    {
        var metadata = new MetadataClient(new InProcessHttpClient(stub));
        var jwks = new JwksClient(new InProcessHttpClient(stub));
        var validator = new AuthTokenResponseValidator(metadata, jwks);
        var signedClient = new InProcessHttpClient(stub) { BaseAddress = new Uri(AsIssuer) };
        return new AccessServerClient(signedClient, metadata, validator);
    }

    private static HttpResponseMessage Ok(string authToken) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                new JsonObject { ["auth_token"] = authToken, ["expires_in"] = 3600 }.ToJsonString(),
                Encoding.UTF8,
                "application/json"),
        };

    private static ValueTask<string> BuildAuthTokenAsync(AAuthKey agentKey, string audience, string scope) =>
        new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = AsIssuer,
            Audience = audience,
            PersonServer = PsIssuer,
            AgentConfirmationKey = agentKey,
            Key = AsKey,
            KeyId = AsKid,
            Dwk = AuthTokenBuilder.AccessDwk,
            Scope = scope,
            Subject = Subject,
        }.BuildAsync();

    /// <summary>
    /// Stub AS: serves <c>aauth-access.json</c> + JWKS for discovery, and a
    /// configurable <c>POST /token</c> response captured per-test.
    /// </summary>
    private sealed class StubAccessServer : HttpMessageHandler
    {
        private readonly Func<HttpResponseMessage> _tokenResponse;
        private readonly Func<JsonObject?, HttpResponseMessage>? _claimsResponse;
        private readonly Func<HttpResponseMessage>? _pendingGetResponse;

        public JsonObject? LastTokenRequestBody { get; private set; }

        public JsonObject? LastClaimsPushBody { get; private set; }

        public StubAccessServer(
            Func<HttpResponseMessage> tokenResponse,
            Func<JsonObject?, HttpResponseMessage>? claimsResponse = null,
            Func<HttpResponseMessage>? pendingGetResponse = null)
        {
            _tokenResponse = tokenResponse;
            _claimsResponse = claimsResponse;
            _pendingGetResponse = pendingGetResponse;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var key = $"{uri.Host}{uri.AbsolutePath}";

            // Deferred poll — GET the pending Location (interaction or escalated
            // requirement=claims).
            if (request.Method == HttpMethod.Get
                && uri.AbsolutePath.StartsWith("/pending/", StringComparison.Ordinal))
            {
                return _pendingGetResponse is not null
                    ? _pendingGetResponse()
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            // §Claims Required push — the PS POSTs directed sub + claims to the
            // pending Location.
            if (request.Method == HttpMethod.Post
                && uri.AbsolutePath.StartsWith("/pending/", StringComparison.Ordinal))
            {
                var rawPush = request.Content is null
                    ? null
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                LastClaimsPushBody = rawPush is null ? null : JsonNode.Parse(rawPush) as JsonObject;
                return _claimsResponse is not null
                    ? _claimsResponse(LastClaimsPushBody)
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (request.Method == HttpMethod.Post && key == "as.test/token")
            {
                var raw = request.Content is null
                    ? null
                    : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                LastTokenRequestBody = raw is null ? null : JsonNode.Parse(raw) as JsonObject;
                return _tokenResponse();
            }

            string? json = key switch
            {
                "as.test/.well-known/aauth-access.json" => new JsonObject
                {
                    ["issuer"] = AsIssuer,
                    ["jwks_uri"] = $"{AsIssuer}/.well-known/jwks.json",
                    ["auth_token_endpoint"] = $"{AsIssuer}/token",
                }.ToJsonString(),
                "as.test/.well-known/jwks.json" => Jwks(AsKey, AsKid),
                _ => null,
            };

            if (json is null)
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        }

        private static string Jwks(AAuthKey key, string kid)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Ed25519Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }
}
