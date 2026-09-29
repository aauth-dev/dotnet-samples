using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Receiver-side conformance for an <c>aa-auth+jwt</c> per §Auth Token Verification.
/// </summary>
public class AuthTokenVerificationTests
{
    private const string Iss = "https://ps.example";
    private const string Aud = "https://resource.example";
    private const string Kid = "ps-1";

    private static (string Jwt, AAuthKey PsKey, AAuthKey AgentKey) GoodToken()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = Iss,
            Audience = Aud,
            PersonServer = Iss,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "pairwise-sub",
            Scope = "whoami",
        }.Build();
        return (jwt, psKey, agentKey);
    }

    private static JsonObject ManualPayload(AAuthKey agentKey, string dwk = "aauth-person.json")
    {
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = dwk, ["aud"] = Aud, ["ps"] = Iss,
            ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = iat + 3600, ["jti"] = "t1",
        };
    }

    private static string Sign(JsonObject payload, AAuthKey psKey) => JwtWriter.SignCompact(
        new JsonObject { ["alg"] = "Ed25519", ["typ"] = "aa-auth+jwt", ["kid"] = Kid }, payload, psKey);

    [Fact(DisplayName = "§Auth Token Verification — accepts well-formed auth token")]
    public void HappyPath_Verifies()
    {
        var (jwt, psKey, agentKey) = GoodToken();
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var verified = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey);
        Assert.Equal(AuthTokenBuilder.TokenType, verified.TokenType);
        Assert.Equal("pairwise-sub", verified.Subject);
        Assert.Equal(Iss, (string?)verified.Payload["ps"]);
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject alg=none")]
    public void Rejects_AlgNone()
    {
        var agentKey = AAuthKey.Generate();
        var header = $"{{\"alg\":\"none\",\"typ\":\"aa-auth+jwt\",\"kid\":\"{Kid}\"}}";
        var jwt = $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(ManualPayload(agentKey).ToJsonString())}.AAAA";

        var psKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(jwt, psKey, Aud, agentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject expired tokens")]
    public void Rejects_Expired()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var issued = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var jwt = new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = Iss,
            Audience = Aud,
            PersonServer = Iss,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "sub",
            IssuedAt = issued,
            TimeProvider = new IssuanceTestClock(issued),
            Lifetime = TimeSpan.FromSeconds(1),
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy, TimeProvider = new IssuanceTestClock(issued.AddHours(2)) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject wrong aud")]
    public void Rejects_WrongAudience()
    {
        var (jwt, psKey, agentKey) = GoodToken();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(jwt, psKey, "https://other.example", agentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject cnf.jwk ≠ HTTP sig key (PoP mismatch)")]
    public void Rejects_CnfMismatch()
    {
        var (jwt, psKey, _) = GoodToken();
        var differentKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(jwt, psKey, Aud, differentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — a token naming ps and sub (no agent, no act) verifies")]
    public void Accepts_PersonNamedToken()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }
            .VerifyAuthToken(Sign(ManualPayload(agentKey), psKey), psKey, Aud, agentKey);
        Assert.Equal(AuthTokenBuilder.TokenType, verified.TokenType);
    }

    [Theory(DisplayName = "§Auth Token Verification — MUST reject a token missing sub or ps")]
    [InlineData("sub")]
    [InlineData("ps")]
    public void Rejects_MissingSubOrPs(string claim)
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var payload = ManualPayload(agentKey);
        payload["scope"] = "whoami";
        payload.Remove(claim);

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(Sign(payload, psKey), psKey, Aud, agentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject dwk not in allowed set")]
    public void Rejects_InvalidDwk()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = Sign(ManualPayload(agentKey, "aauth-resource.json"), psKey);

        // Verifier in dual-dwk mode (expectedDwk=null) rejects aauth-resource.json
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: null));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject a person token where an auth token is required")]
    public void Rejects_PersonToken()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var personToken = new PersonTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = Iss,
            Audience = Aud,
            Subject = "pairwise-sub",
            ConfirmationKey = agentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Key = psKey,
            KeyId = Kid,
        }.Build();

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(personToken, psKey, Aud, agentKey));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject signature from different key")]
    public void Rejects_WrongSignatureKey()
    {
        var (jwt, _, agentKey) = GoodToken();
        var wrongPsKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(jwt, wrongPsKey, Aud, agentKey));
    }
}
