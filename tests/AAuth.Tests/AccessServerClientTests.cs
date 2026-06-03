using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
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
    private const string ResourceUrl = "https://whoami.test";
    private const string AgentId = "aauth:demo@ap.test";
    private const string AsKid = "as-1";

    private static readonly AAuthKey AsKey = AAuthKey.Generate();

    [Fact]
    public async Task FederateAsync_ReturnsVerifiedAuthToken_OnSuccess()
    {
        var agentKey = AAuthKey.Generate();
        var authToken = BuildAuthToken(agentKey, audience: ResourceUrl, scope: "whoami");
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
        var authToken = BuildAuthToken(agentKey, audience: ResourceUrl, scope: "whoami");
        var stub = new StubAccessServer(() => Ok(authToken));
        var client = BuildClient(stub);

        await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            UpstreamToken = "the-upstream-token",
            ExpectedAudience = ResourceUrl,
            ExpectedAgentId = AgentId,
            AgentKey = agentKey,
            RequestedScope = "whoami",
        });

        Assert.Equal("the-upstream-token", (string?)stub.LastTokenRequestBody!["upstream_token"]);
    }

    [Fact]
    public async Task FederateAsync_ThrowsPaymentRequired_On402()
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
            response.Headers.Location = new Uri("https://pay.as.test/invoice/42");
            response.Headers.TryAddWithoutValidation("WWW-Authenticate", "x402 realm=\"as.test\"");
            return response;
        });
        var client = BuildClient(stub);

        var ex = await Assert.ThrowsAsync<AAuthPaymentRequiredException>(
            () => client.FederateAsync(AsIssuer, NewRequest(agentKey)));

        Assert.Equal("https://pay.as.test/invoice/42", ex.Location);
        Assert.Contains("x402", ex.Challenge);
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
        var authToken = BuildAuthToken(agentKey, audience: ResourceUrl, scope: "whoami");

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

        AAuthClaimsRequirement? seen = null;
        var result = await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            ExpectedAudience = ResourceUrl,
            ExpectedAgentId = AgentId,
            AgentKey = agentKey,
            RequestedScope = "whoami",
            OnClaimsRequired = (requirement, _) =>
            {
                seen = requirement;
                return Task.FromResult(new AAuthClaimsResponse
                {
                    Subject = "directed-123",
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
        // The directed sub + claims were POSTed (signed) to the pending URL.
        Assert.NotNull(stub.LastClaimsPushBody);
        Assert.Equal("directed-123", (string?)stub.LastClaimsPushBody!["sub"]);
        Assert.Equal("demo@person.example", (string?)stub.LastClaimsPushBody["email"]);
    }

    [Fact]
    public async Task FederateAsync_ThrowsInvalidOperation_WhenClaimsHandlerOmitsSub()
    {
        var agentKey = AAuthKey.Generate();
        var stub = new StubAccessServer(
            tokenResponse: () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Accepted)
                {
                    Content = new StringContent(
                        new JsonObject { ["required_claims"] = new JsonArray("email") }.ToJsonString(),
                        Encoding.UTF8,
                        "application/json"),
                };
                response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=claims");
                response.Headers.Location = new Uri($"{AsIssuer}/pending/abc");
                return response;
            });
        var client = BuildClient(stub);

        // The handler returns claims WITHOUT the mandatory directed sub.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.FederateAsync(AsIssuer, new AccessServerRequest
            {
                ResourceToken = "the-resource-token",
                AgentToken = "the-agent-token",
                ExpectedAudience = ResourceUrl,
                ExpectedAgentId = AgentId,
                AgentKey = agentKey,
                RequestedScope = "whoami",
                OnClaimsRequired = (_, _) => Task.FromResult(
                    new AAuthClaimsResponse { Subject = string.Empty }),
            }));

        Assert.Contains("sub", ex.Message);
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
        var authToken = BuildAuthToken(agentKey, audience: ResourceUrl, scope: "whoami");

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
        AAuthClaimsRequirement? claimsSeen = null;
        var result = await client.FederateAsync(AsIssuer, new AccessServerRequest
        {
            ResourceToken = "the-resource-token",
            AgentToken = "the-agent-token",
            ExpectedAudience = ResourceUrl,
            ExpectedAgentId = AgentId,
            AgentKey = agentKey,
            RequestedScope = "whoami",
            OnInteractionRequired = (_, _) => { interactionSeen = true; return Task.CompletedTask; },
            OnClaimsRequired = (requirement, _) =>
            {
                claimsSeen = requirement;
                return Task.FromResult(new AAuthClaimsResponse
                {
                    Subject = "directed-xyz",
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
        Assert.Equal("directed-xyz", (string?)stub.LastClaimsPushBody!["sub"]);
    }
    [Fact]
    public async Task FederateAsync_ThrowsVerification_WhenAudienceMismatch()
    {
        var agentKey = AAuthKey.Generate();
        // The AS mints a token for a DIFFERENT resource than the PS expects.
        var authToken = BuildAuthToken(agentKey, audience: "https://evil.test", scope: "whoami");
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
                    ["error_description"] = "aud mismatch",
                }.ToJsonString(),
                Encoding.UTF8,
                "application/json"),
        });
        var client = BuildClient(stub);

        var ex = await Assert.ThrowsAsync<AAuthTokenExchangeException>(
            () => client.FederateAsync(AsIssuer, NewRequest(agentKey)));

        Assert.Equal("invalid_resource_token", ex.ErrorCode);
        Assert.Equal(400, ex.StatusCode);
    }

    // -- helpers ---------------------------------------------------------

    private static AccessServerRequest NewRequest(AAuthKey agentKey) => new()
    {
        ResourceToken = "the-resource-token",
        AgentToken = "the-agent-token",
        ExpectedAudience = ResourceUrl,
        ExpectedAgentId = AgentId,
        AgentKey = agentKey,
        RequestedScope = "whoami",
    };

    private static AccessServerClient BuildClient(StubAccessServer stub)
    {
        var metadata = new MetadataClient(new HttpClient(stub));
        var jwks = new JwksClient(new HttpClient(stub));
        var validator = new AuthTokenResponseValidator(metadata, jwks);
        var signedClient = new HttpClient(stub) { BaseAddress = new Uri(AsIssuer) };
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

    private static string BuildAuthToken(AAuthKey agentKey, string audience, string scope) =>
        new AuthTokenBuilder
        {
            Issuer = AsIssuer,
            Audience = audience,
            Agent = AgentId,
            AgentConfirmationKey = agentKey,
            Key = AsKey,
            KeyId = AsKid,
            Dwk = AuthTokenBuilder.AccessDwk,
            Scope = scope,
            Subject = "pairwise-sub",
        }.Build();

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
                    ["token_endpoint"] = $"{AsIssuer}/token",
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
            jwk["alg"] = AAuthKey.Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }
}
