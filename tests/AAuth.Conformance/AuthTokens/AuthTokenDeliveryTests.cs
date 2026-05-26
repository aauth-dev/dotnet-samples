using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Tests for AuthTokenResponseValidator per §Auth Token Delivery steps 1–7.
/// </summary>
public class AuthTokenDeliveryTests
{
    private const string AsIssuer = "http://localhost:5300";
    private const string ResourceAudience = "http://localhost:5200";
    private const string AgentId = "aauth:agent@example";
    private const string AsKid = "as-1";

    private readonly AAuthKey _asKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    private string BuildAuthToken(
        string? issuer = null,
        string? audience = null,
        string? agent = null,
        IAAuthKey? agentConfirmationKey = null,
        string? scope = null,
        JsonObject? upstreamAct = null)
    {
        return new AuthTokenBuilder
        {
            Issuer = issuer ?? AsIssuer,
            Audience = audience ?? ResourceAudience,
            Agent = agent ?? AgentId,
            AgentConfirmationKey = agentConfirmationKey ?? _agentKey,
            Key = _asKey,
            KeyId = AsKid,
            Scope = scope ?? "data.read",
            Subject = "user-123",
            UpstreamAct = upstreamAct,
            Dwk = AuthTokenBuilder.AccessDwk,
        }.Build();
    }

    private AuthTokenResponseValidator CreateValidator()
    {
        var mockHandler = new MockAsHandler(_asKey, AsKid, AsIssuer);
        var httpClient = new HttpClient(mockHandler);
        var metadata = new MetadataClient(httpClient);
        var jwks = new JwksClient(httpClient);
        return new AuthTokenResponseValidator(metadata, jwks);
    }

    [Fact(DisplayName = "§Auth Token Delivery — valid token accepted")]
    public async Task ValidToken_Accepted()
    {
        var token = BuildAuthToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, _agentKey);

        Assert.True(result.IsValid);
        Assert.Null(result.Error);
        Assert.NotNull(result.Verified);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 2: issuer mismatch rejected")]
    public async Task IssuerMismatch_Rejected()
    {
        var token = BuildAuthToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(
            token, "http://localhost:9999", ResourceAudience, AgentId, _agentKey);

        Assert.False(result.IsValid);
        Assert.Contains("issuer_mismatch", result.Error);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 3: audience mismatch rejected")]
    public async Task AudienceMismatch_Rejected()
    {
        var token = BuildAuthToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(
            token, AsIssuer, "http://localhost:9999", AgentId, _agentKey);

        Assert.False(result.IsValid);
        Assert.Contains("aud", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 4: agent mismatch rejected")]
    public async Task AgentMismatch_Rejected()
    {
        var token = BuildAuthToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, "aauth:wrong@example", _agentKey);

        Assert.False(result.IsValid);
        Assert.Contains("agent", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 5: cnf.jwk mismatch rejected")]
    public async Task ConfirmationKeyMismatch_Rejected()
    {
        var token = BuildAuthToken();
        var validator = CreateValidator();
        var wrongKey = AAuthKey.Generate();

        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, wrongKey);

        Assert.False(result.IsValid);
        Assert.Contains("cnf.jwk", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 6: act chain matches upstream context")]
    public async Task ActChainMatchesUpstreamContext()
    {
        // Simulate call chaining: upstream act has an original agent
        var upstreamAct = new JsonObject { ["sub"] = "aauth:original@example" };
        var token = BuildAuthToken(upstreamAct: upstreamAct);
        var validator = CreateValidator();

        // PS passes the expected upstream context (what it used to construct the act)
        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, _agentKey,
            expectedActContext: upstreamAct);

        Assert.True(result.IsValid);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 6: act chain mismatch rejected")]
    public async Task ActChainMismatch_Rejected()
    {
        var upstreamAct = new JsonObject { ["sub"] = "aauth:original@example" };
        var token = BuildAuthToken(upstreamAct: upstreamAct);
        var validator = CreateValidator();

        // PS expects a different chain
        var wrongContext = new JsonObject { ["sub"] = "aauth:attacker@example" };
        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, _agentKey,
            expectedActContext: wrongContext);

        Assert.False(result.IsValid);
        Assert.Contains("act_chain_mismatch", result.Error);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 7: scope escalation rejected")]
    public async Task ScopeEscalation_Rejected()
    {
        var token = BuildAuthToken(scope: "data.read data.write");
        var validator = CreateValidator();

        // Resource token only requested data.read
        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, _agentKey,
            requestedScope: "data.read");

        Assert.False(result.IsValid);
        Assert.Contains("scope", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — step 7: scope narrowing accepted")]
    public async Task ScopeNarrowing_Accepted()
    {
        var token = BuildAuthToken(scope: "data.read");
        var validator = CreateValidator();

        // Token scope is subset of requested — valid
        var result = await validator.ValidateAsync(
            token, AsIssuer, ResourceAudience, AgentId, _agentKey,
            requestedScope: "data.read data.write");

        Assert.True(result.IsValid);
    }

    /// <summary>
    /// Mock HTTP handler that serves AS metadata + JWKS.
    /// </summary>
    private sealed class MockAsHandler : HttpMessageHandler
    {
        private readonly AAuthKey _key;
        private readonly string _kid;
        private readonly string _issuer;

        public MockAsHandler(AAuthKey key, string kid, string issuer)
        {
            _key = key;
            _kid = kid;
            _issuer = issuer;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? "";

            if (path.EndsWith("aauth-access.json"))
            {
                var meta = new JsonObject
                {
                    ["issuer"] = _issuer,
                    ["jwks_uri"] = $"{_issuer}/.well-known/jwks.json",
                    ["token_endpoint"] = $"{_issuer}/token",
                };
                return JsonResponse(meta);
            }

            if (path.EndsWith("jwks.json"))
            {
                var jwk = _key.ToPublicJwk();
                jwk["kid"] = _kid;
                jwk["use"] = "sig";
                jwk["alg"] = AAuthKey.Algorithm;
                var jwks = new JsonObject
                {
                    ["keys"] = new JsonArray { jwk },
                };
                return JsonResponse(jwks);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonResponse(JsonObject json)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    json.ToJsonString(),
                    System.Text.Encoding.UTF8,
                    "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}
