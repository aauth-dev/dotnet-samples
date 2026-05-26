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
/// Tests for UpstreamTokenValidator per §Upstream Token Verification.
/// Uses a mock HTTP handler to simulate metadata and JWKS endpoints.
/// </summary>
public class UpstreamTokenValidationTests
{
    private const string PsIssuer = "http://localhost:5100";
    private const string ResourceAudience = "http://localhost:5200";
    private const string AgentId = "aauth:agent@example";
    private const string PsKid = "ps-1";

    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    private string BuildValidUpstreamToken(
        string? issuer = null,
        string? audience = null,
        string? agent = null,
        JsonObject? upstreamAct = null)
    {
        return new AuthTokenBuilder
        {
            Issuer = issuer ?? PsIssuer,
            Audience = audience ?? ResourceAudience,
            Agent = agent ?? AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = PsKid,
            Scope = "data.read",
            Subject = "user-123",
            UpstreamAct = upstreamAct,
        }.Build();
    }

    private UpstreamTokenValidator CreateValidator()
    {
        var mockHandler = new MockJwksHandler(_psKey, PsKid, PsIssuer);
        var httpClient = new HttpClient(mockHandler);
        var metadata = new MetadataClient(httpClient);
        var jwks = new JwksClient(httpClient);
        return new UpstreamTokenValidator(metadata, jwks);
    }

    [Fact(DisplayName = "§Upstream Token Verification — valid token accepted")]
    public async Task ValidToken_Accepted()
    {
        var token = BuildValidUpstreamToken();
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        Assert.Null(result.Error);
        Assert.NotNull(result.UpstreamAct);
        Assert.Equal(PsIssuer, result.Issuer);
        Assert.Equal(AgentId, result.Agent);
        Assert.Equal("user-123", result.Subject);
        Assert.Equal("data.read", result.Scope);
    }

    [Fact(DisplayName = "§Upstream Token Verification — untrusted issuer rejected")]
    public async Task UntrustedIssuer_Rejected()
    {
        var token = BuildValidUpstreamToken();
        var validator = CreateValidator();
        var trusted = new HashSet<string> { "https://other-ps.example" }; // PS not trusted

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.False(result.IsValid);
        Assert.Contains("untrusted_issuer", result.Error);
    }

    [Fact(DisplayName = "§Upstream Token Verification — audience mismatch rejected")]
    public async Task AudienceMismatch_Rejected()
    {
        var token = BuildValidUpstreamToken(audience: "http://localhost:9999");
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.False(result.IsValid);
        Assert.Contains("aud", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Upstream Token Verification — expired token rejected")]
    public async Task ExpiredToken_Rejected()
    {
        // Build a token that's already expired
        var token = new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceAudience,
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = PsKid,
            Scope = "data.read",
            IssuedAt = DateTimeOffset.UtcNow - TimeSpan.FromHours(2),
            Lifetime = TimeSpan.FromMinutes(5),
        }.Build();

        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.False(result.IsValid);
        Assert.Contains("expired", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Upstream Token Verification — returns UpstreamAct for nesting")]
    public async Task ValidToken_ReturnsUpstreamAct()
    {
        // Token with a nested act (simulating a 2-hop chain)
        var innerAct = new JsonObject { ["sub"] = "aauth:original@example" };
        var token = BuildValidUpstreamToken(upstreamAct: innerAct);
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        Assert.NotNull(result.UpstreamAct);
        // The act claim should have sub = AgentId, act = { sub = "original" }
        Assert.Equal(AgentId, (string?)result.UpstreamAct!["sub"]);
        var nested = result.UpstreamAct["act"] as JsonObject;
        Assert.NotNull(nested);
        Assert.Equal("aauth:original@example", (string?)nested!["sub"]);
    }

    [Fact(DisplayName = "§Upstream Token Verification — returns raw upstream act for nesting")]
    public async Task ReturnsRawUpstreamAct()
    {
        var token = BuildValidUpstreamToken();
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        Assert.NotNull(result.UpstreamAct);
        // UpstreamAct returns the RAW upstream act (not pre-nested).
        // AuthTokenBuilder performs the nesting: { sub: intermediary, act: UpstreamAct }.
        Assert.Equal(AgentId, (string?)result.UpstreamAct!["sub"]);
    }

    [Fact(DisplayName = "§Upstream Token Verification — chain depth exceeded rejected")]
    public async Task ChainDepthExceeded_Rejected()
    {
        // Build a deeply nested act chain that exceeds MaxActDepth (default 10).
        // AuthTokenBuilder wraps UpstreamAct inside act { sub: agent, act: upstreamAct },
        // so total depth = nested depth + 1. Build 10 levels so total = 11 > max 10.
        JsonObject act = new JsonObject { ["sub"] = "aauth:deep10@example" };
        for (int i = 9; i >= 1; i--)
        {
            act = new JsonObject { ["sub"] = $"aauth:deep{i}@example", ["act"] = act };
        }

        // Use a custom agent that matches the outermost act.sub that AuthTokenBuilder will set
        var token = BuildValidUpstreamToken(agent: AgentId, upstreamAct: act);
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.False(result.IsValid);
        Assert.Contains("invalid_act_chain", result.Error);
    }

    /// <summary>
    /// Mock HTTP handler that serves metadata + JWKS for the test PS.
    /// </summary>
    private sealed class MockJwksHandler : HttpMessageHandler
    {
        private readonly AAuthKey _key;
        private readonly string _kid;
        private readonly string _issuer;

        public MockJwksHandler(AAuthKey key, string kid, string issuer)
        {
            _key = key;
            _kid = kid;
            _issuer = issuer;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? "";

            if (path.EndsWith("aauth-person.json"))
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
