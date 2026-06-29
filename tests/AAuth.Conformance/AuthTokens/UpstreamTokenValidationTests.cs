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
        JsonObject? upstreamAct = null,
        string? dwk = null,
        MissionClaim? mission = null)
    {
        return new AuthTokenBuilder
        {
            Issuer = issuer ?? PsIssuer,
            Audience = audience ?? ResourceAudience,
            Agent = agent ?? AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = PsKid,
            Dwk = dwk ?? AuthTokenBuilder.PersonDwk,
            Scope = "data.read",
            Subject = "user-123",
            Act = upstreamAct,
            Mission = mission,
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
        // A direct-auth upstream token carries no act (OPTIONAL in draft-08).
        Assert.Null(result.UpstreamAct);
        Assert.Equal(PsIssuer, result.Issuer);
        Assert.Equal(AgentId, result.Agent);
        Assert.Equal("user-123", result.Subject);
        Assert.Equal("data.read", result.Scope);
        // A PS-issued upstream token reports dwk = aauth-person.json and no mission.
        Assert.Equal(AuthTokenBuilder.PersonDwk, result.IssuerDwk);
        Assert.Null(result.MissionApprover);
    }

    [Fact(DisplayName = "§Upstream Token Verification — AS-issued (dwk) and mission approver surfaced")]
    public async Task IssuerDwkAndMissionApprover_Surfaced()
    {
        const string Approver = "https://ps.governing";
        const string S256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var token = BuildValidUpstreamToken(
            dwk: AuthTokenBuilder.AccessDwk,
            mission: new MissionClaim(Approver, S256));
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        // The four-party discriminator: dwk = aauth-access.json identifies an AS issuer.
        Assert.Equal(AuthTokenBuilder.AccessDwk, result.IssuerDwk);
        // mission.approver anchors the chain to a governing PS.
        Assert.Equal(Approver, result.MissionApprover);
    }

    [Fact(DisplayName = "§Upstream Token Verification — an out-of-set dwk is rejected")]
    public async Task OutOfSetDwk_Rejected()
    {
        // A token whose dwk is neither aauth-person.json nor aauth-access.json must
        // be rejected — the four-party mission gate classifies AS vs PS from dwk.
        var token = BuildValidUpstreamToken(dwk: "aauth-resource.json");
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.False(result.IsValid);
        Assert.Contains("dwk", result.Error, StringComparison.OrdinalIgnoreCase);
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

    [Fact(DisplayName = "§Upstream Token Verification — predicate may reject an otherwise-valid issuer")]
    public async Task PredicateRejectsIssuer_Rejected()
    {
        var token = BuildValidUpstreamToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(token, ResourceAudience, isTrustedIssuer: _ => false);

        Assert.False(result.IsValid);
        Assert.Contains("untrusted_issuer", result.Error);
    }

    [Fact(DisplayName = "§Upstream Token Verification — predicate authorizes a trusted issuer")]
    public async Task PredicateAcceptsIssuer_Accepted()
    {
        var token = BuildValidUpstreamToken();
        var validator = CreateValidator();

        var result = await validator.ValidateAsync(token, ResourceAudience, isTrustedIssuer: iss => iss == PsIssuer);

        Assert.True(result.IsValid);
        Assert.Equal(PsIssuer, result.Issuer);
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
        // Token whose act is itself a 2-hop chain (the upstream was already chained).
        var innerAct = ActChainBuilder.BuildNestedAct(
            "aauth:intermediary@example",
            new JsonObject { ["agent"] = "aauth:original@example" });
        var token = BuildValidUpstreamToken(upstreamAct: innerAct);
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        Assert.NotNull(result.UpstreamAct);
        // The validator returns the token's raw act unchanged: { agent: intermediary, act: { agent: original } }.
        Assert.Equal("aauth:intermediary@example", (string?)result.UpstreamAct!["agent"]);
        var nested = result.UpstreamAct["act"] as JsonObject;
        Assert.NotNull(nested);
        Assert.Equal("aauth:original@example", (string?)nested!["agent"]);
    }

    [Fact(DisplayName = "§Upstream Token Verification — returns raw upstream act for nesting")]
    public async Task ReturnsRawUpstreamAct()
    {
        // The validator returns the upstream token's raw act unchanged (no wrapping).
        var rawAct = new JsonObject { ["agent"] = "aauth:original@example" };
        var token = BuildValidUpstreamToken(upstreamAct: rawAct);
        var validator = CreateValidator();
        var trusted = new HashSet<string> { PsIssuer };

        var result = await validator.ValidateAsync(token, ResourceAudience, trusted);

        Assert.True(result.IsValid);
        Assert.NotNull(result.UpstreamAct);
        Assert.Equal("aauth:original@example", (string?)result.UpstreamAct!["agent"]);
    }

    [Fact(DisplayName = "§Upstream Token Verification — chain depth exceeded rejected")]
    public async Task ChainDepthExceeded_Rejected()
    {
        // Build a deeply nested act chain that exceeds MaxActDepth (default 10).
        // In draft-08 the Act node is emitted verbatim (no extra wrapping), so build
        // 11 levels directly so total depth = 11 > max 10.
        JsonObject act = new JsonObject { ["agent"] = "aauth:deep11@example" };
        for (int i = 10; i >= 1; i--)
        {
            act = new JsonObject { ["agent"] = $"aauth:deep{i}@example", ["act"] = act };
        }

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

            if (path.EndsWith(".json"))
            {
                // Serve metadata for any well-known document name (person, access,
                // or — for negative dwk tests — anything else) so the validator's
                // own dwk allow-list, not a 404, is what rejects an out-of-set dwk.
                var meta = new JsonObject
                {
                    ["issuer"] = _issuer,
                    ["jwks_uri"] = $"{_issuer}/.well-known/jwks.json",
                    ["token_endpoint"] = $"{_issuer}/token",
                };
                return JsonResponse(meta);
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
