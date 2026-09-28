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
/// Tests for UpstreamTokenValidator per §Upstream Token Verification. The
/// upstream token is a person token or an auth token whose <c>aud</c> is the
/// intermediary and whose person server is the expected PS.
/// </summary>
public class UpstreamTokenValidationTests
{
    private const string PsIssuer = "http://localhost:5100";
    private const string AsIssuer = "http://localhost:5300";
    private const string Intermediary = "http://localhost:5200";
    private const string PsKid = "ps-1";
    private const string AsKid = "as-1";
    private const string S256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _asKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    [Theory]
    [InlineData("missing-cnf")]
    [InlineData("incomplete-key")]
    [InlineData("private-key")]
    [InlineData("missing-sub")]
    public async Task SignedButStructurallyInvalidUpstreamIsRejected(string variant)
    {
        var segments = BuildAuthToken().Split('.');
        var header = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[0]))!.AsObject();
        var payload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!.AsObject();
        switch (variant)
        {
            case "missing-cnf": payload.Remove("cnf"); break;
            case "incomplete-key": payload["cnf"]!["jwk"]!.AsObject().Remove("x"); break;
            case "private-key": payload["cnf"]!["jwk"]!["d"] = "private"; break;
            case "missing-sub": payload.Remove("sub"); break;
        }
        var result = await Validate(JwtWriter.SignCompact(header, payload, _psKey));
        Assert.False(result.IsValid);
        Assert.NotNull(result.Error);
    }

    private string BuildAuthToken(
        string? issuer = null,
        string? audience = null,
        string? personServer = null,
        string? dwk = null,
        string? missionS256 = null,
        AAuthKey? key = null,
        string? kid = null)
    {
        return new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Issuer = issuer ?? PsIssuer,
            Audience = audience ?? Intermediary,
            PersonServer = personServer ?? PsIssuer,
            Subject = "user-123",
            AgentConfirmationKey = _agentKey,
            Key = key ?? _psKey,
            KeyId = kid ?? PsKid,
            Dwk = dwk ?? AuthTokenBuilder.PersonDwk,
            Scope = "data.read",
            MissionS256 = missionS256,
        }.Build();
    }

    private string BuildAsAuthToken(string? missionS256 = null) => BuildAuthToken(
        issuer: AsIssuer, dwk: AuthTokenBuilder.AccessDwk, missionS256: missionS256, key: _asKey, kid: AsKid);

    private string BuildPersonToken(string? issuer = null, string? audience = null, string? tenant = null) => new PersonTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = issuer ?? PsIssuer,
        Audience = audience ?? Intermediary,
        Subject = "user-123",
        ConfirmationKey = _agentKey,
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        Key = _psKey,
        KeyId = PsKid,
        MissionS256 = S256,
        Tenant = tenant,
    }.Build();

    private UpstreamTokenValidator CreateValidator()
    {
        var mockHandler = new MockJwksHandler(new()
        {
            [PsIssuer] = (_psKey, PsKid),
            [AsIssuer] = (_asKey, AsKid),
        });
        var httpClient = new InProcessHttpClient(mockHandler);
        var metadata = new MetadataClient(httpClient);
        var jwks = new JwksClient(httpClient);
        return new UpstreamTokenValidator(metadata, jwks);
    }

    private Task<UpstreamTokenValidationResult> Validate(string token, Func<string, bool>? trusted = null) =>
        CreateValidator().ValidateAsync(token, Intermediary, PsIssuer, trusted ?? (_ => false));

    [Fact(DisplayName = "§Upstream Token Verification — valid PS-issued auth token accepted")]
    public async Task ValidToken_Accepted()
    {
        var result = await Validate(BuildAuthToken());

        Assert.True(result.IsValid);
        Assert.Null(result.Error);
        Assert.Equal(PsIssuer, result.Issuer);
        Assert.Equal(PsIssuer, result.PersonServer);
        Assert.Equal(AuthTokenBuilder.TokenType, result.TokenType);
        Assert.Equal(Intermediary, result.Audience);
        Assert.Equal("user-123", result.Subject);
        Assert.Equal("data.read", result.Scope);
        Assert.Null(result.MissionS256);
        Assert.NotNull(result.ExpiresAt);
    }

    [Fact(DisplayName = "§Upstream Token Verification — valid person token accepted")]
    public async Task ValidPersonToken_Accepted()
    {
        var result = await Validate(BuildPersonToken(tenant: "acme"));

        Assert.True(result.IsValid, result.Error);
        Assert.Equal(PersonTokenBuilder.TokenType, result.TokenType);
        Assert.Equal(PsIssuer, result.Issuer);
        Assert.Equal(PsIssuer, result.PersonServer);
        Assert.Equal("user-123", result.Subject);
        Assert.Equal(S256, result.MissionS256);
        Assert.Equal("acme", result.Tenant);
        Assert.Null(result.Scope);
    }

    [Fact(DisplayName = "§Upstream Token Verification — AS-issued auth token surfaces ps and mission_s256")]
    public async Task AsIssuedToken_SurfacesPersonServerAndMission()
    {
        var result = await Validate(BuildAsAuthToken(S256), iss => iss == AsIssuer);

        Assert.True(result.IsValid, result.Error);
        Assert.Equal(AsIssuer, result.Issuer);
        Assert.Equal(PsIssuer, result.PersonServer);
        Assert.Equal(S256, result.MissionS256);
    }

    [Fact(DisplayName = "§Upstream Token Verification — an out-of-set dwk is rejected")]
    public async Task OutOfSetDwk_Rejected()
    {
        var result = await Validate(BuildAuthToken(dwk: "aauth-resource.json"));

        Assert.False(result.IsValid);
        Assert.Contains("dwk", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Upstream Token Verification — auth token from an untrusted AS rejected")]
    public async Task UntrustedIssuer_Rejected()
    {
        var result = await Validate(BuildAsAuthToken());

        Assert.False(result.IsValid);
        Assert.Contains("not trusted", result.Error);
    }

    [Fact(DisplayName = "§Upstream Token Verification — predicate may reject an otherwise-valid AS")]
    public async Task PredicateRejectsIssuer_Rejected()
    {
        var result = await Validate(BuildAsAuthToken(), iss => iss == "http://localhost:9999");

        Assert.False(result.IsValid);
        Assert.Contains("not trusted", result.Error);
    }

    [Fact(DisplayName = "§Upstream Token Verification — the expected PS is trusted without the predicate")]
    public async Task ExpectedPersonServer_TrustedWithoutPredicate()
    {
        var result = await Validate(BuildAuthToken(), _ => false);

        Assert.True(result.IsValid, result.Error);
        Assert.Equal(PsIssuer, result.Issuer);
    }

    [Theory(DisplayName = "§Upstream Token Verification — token naming another person server rejected")]
    [InlineData("auth")]
    [InlineData("person")]
    public async Task OtherPersonServer_Rejected(string kind)
    {
        var token = kind == "auth"
            ? BuildAuthToken(personServer: "http://localhost:9999")
            : BuildPersonToken();
        var result = await CreateValidator().ValidateAsync(token, Intermediary,
            kind == "auth" ? PsIssuer : "http://localhost:9999", _ => true);

        Assert.False(result.IsValid);
        Assert.Contains("person server", result.Error);
    }

    [Theory(DisplayName = "§Upstream Token Verification — audience mismatch rejected")]
    [InlineData("auth")]
    [InlineData("person")]
    public async Task AudienceMismatch_Rejected(string kind)
    {
        var token = kind == "auth"
            ? BuildAuthToken(audience: "http://localhost:9999")
            : BuildPersonToken(audience: "http://localhost:9999");
        var result = await Validate(token);

        Assert.False(result.IsValid);
        Assert.Contains("aud", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Upstream Token Verification — agent token rejected as upstream")]
    public async Task AgentToken_Rejected()
    {
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = PsIssuer,
            Subject = "aauth:agent@localhost",
            ConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = PsKid,
        }.Build();

        var result = await Validate(agentToken);

        Assert.False(result.IsValid);
    }

    [Fact(DisplayName = "§Upstream Token Verification — expired token rejected")]
    public async Task ExpiredToken_Rejected()
    {
        var token = new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Issuer = PsIssuer,
            Audience = Intermediary,
            PersonServer = PsIssuer,
            Subject = "user-123",
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = PsKid,
            Scope = "data.read",
            IssuedAt = DateTimeOffset.UtcNow - TimeSpan.FromHours(2),
            TimeProvider = new IssuanceTestClock(DateTimeOffset.UtcNow - TimeSpan.FromHours(2)),
            Lifetime = TimeSpan.FromMinutes(5),
        }.Build();

        var result = await Validate(token);

        Assert.False(result.IsValid);
        Assert.Contains("expired", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Serves metadata + JWKS for each configured issuer.</summary>
    private sealed class MockJwksHandler(Dictionary<string, (AAuthKey Key, string Kid)> issuers) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var issuer = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            if (!issuers.TryGetValue(issuer, out var entry))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var path = request.RequestUri.AbsolutePath;

            if (path.EndsWith("jwks.json"))
            {
                var jwk = entry.Key.ToPublicJwk();
                jwk["kid"] = entry.Kid;
                jwk["use"] = "sig";
                jwk["alg"] = AAuthKey.Ed25519Algorithm;
                return JsonResponse(new JsonObject { ["keys"] = new JsonArray { jwk } });
            }

            if (path.EndsWith(".json"))
            {
                // Serve metadata for any well-known document name so the verifier's
                // own dwk allow-list, not a 404, is what rejects an out-of-set dwk.
                return JsonResponse(new JsonObject
                {
                    ["issuer"] = issuer,
                    ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
                    ["token_endpoint"] = $"{issuer}/token",
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonResponse(JsonObject json) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json.ToJsonString(), System.Text.Encoding.UTF8, "application/json"),
            });
    }
}
