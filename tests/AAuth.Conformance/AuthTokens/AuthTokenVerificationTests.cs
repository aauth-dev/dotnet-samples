using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Receiver-side conformance for an <c>aa-auth+jwt</c> per
/// draft-hardt-oauth-aauth-protocol-01 §Auth Token Verification.
/// </summary>
public class AuthTokenVerificationTests
{
    private const string Iss = "https://ps.example";
    private const string Aud = "https://resource.example";
    private const string Agent = "aauth:alice@ap.example";
    private const string Kid = "ps-1";

    private static (string Jwt, AAuthKey PsKey, AAuthKey AgentKey) GoodToken()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "pairwise-sub",
            Scope = "whoami",
        }.Build();
        return (jwt, psKey, agentKey);
    }

    [Fact(DisplayName = "§Auth Token Verification — accepts well-formed auth token")]
    public void HappyPath_Verifies()
    {
        var (jwt, psKey, agentKey) = GoodToken();
        var verifier = new TokenVerifier();
        var verified = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent);
        Assert.Equal(AuthTokenBuilder.TokenType, verified.TokenType);
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject alg=none")]
    public void Rejects_AlgNone()
    {
        var agentKey = AAuthKey.Generate();
        var header = $"{{\"alg\":\"none\",\"typ\":\"aa-auth+jwt\",\"kid\":\"{Kid}\"}}";
        var payload = $"{{\"iss\":\"{Iss}\",\"dwk\":\"aauth-person.json\",\"aud\":\"{Aud}\",\"agent\":\"{Agent}\",\"cnf\":{{\"jwk\":{agentKey.ToPublicJwk().ToJsonString()}}},\"sub\":\"x\",\"iat\":1,\"exp\":9999999999,\"jti\":\"t1\"}}";
        var jwt = $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(payload)}.AAAA";

        var psKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject expired tokens")]
    public void Rejects_Expired()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var issued = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var jwt = new AuthTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "sub",
            IssuedAt = issued,
            Lifetime = TimeSpan.FromSeconds(1),
        }.Build();

        var verifier = new TokenVerifier { Clock = () => issued.AddHours(2) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject wrong aud")]
    public void Rejects_WrongAudience()
    {
        var (jwt, psKey, agentKey) = GoodToken();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, "https://other.example", agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject cnf.jwk ≠ HTTP sig key (PoP mismatch)")]
    public void Rejects_CnfMismatch()
    {
        var (jwt, psKey, _) = GoodToken();
        var differentKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, differentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — direct-auth token (no act) verifies")]
    public void Accepts_MissingActIsDirectAuth()
    {
        // Build a token manually without act — direct authorization. In draft-08
        // `act` is OPTIONAL (§Delegation Chain) and absent for direct authorization.
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-person.json", ["aud"] = Aud,
            ["agent"] = Agent, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
            // No "act" claim — direct authorization.
        };
        var jwt = JwtWriter.SignCompact(headerObj, payloadObj, psKey);

        var verified = new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent);
        Assert.Equal(AuthTokenBuilder.TokenType, verified.TokenType);
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject malformed act.agent")]
    public void Rejects_InvalidActAgent()
    {
        // act.agent that is not a valid AAuth agent identifier is rejected.
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-person.json", ["aud"] = Aud,
            ["agent"] = Agent, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["act"] = new JsonObject { ["agent"] = "not-a-valid-agent-id" },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
        };
        var jwt = JwtWriter.SignCompact(headerObj, payloadObj, psKey);

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject missing both sub and scope")]
    public void Rejects_MissingSubAndScope()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-person.json", ["aud"] = Aud,
            ["agent"] = Agent, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
            // No sub, no scope
        };
        var jwt = JwtWriter.SignCompact(headerObj, payloadObj, psKey);

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject dwk not in allowed set")]
    public void Rejects_InvalidDwk()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-resource.json", ["aud"] = Aud,
            ["agent"] = Agent, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
        };
        var jwt = JwtWriter.SignCompact(headerObj, payloadObj, psKey);

        // Verifier in dual-dwk mode (expectedDwk=null) rejects aauth-resource.json
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent, expectedDwk: null));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject nested act exceeding depth limit")]
    public void Rejects_DeepNestedAct()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;

        // Build nested act 12 levels deep (exceeds default MaxActDepth=10)
        JsonObject innerAct = new() { ["agent"] = "aauth:inner@x.example" };
        for (int i = 0; i < 11; i++)
        {
            innerAct = new JsonObject { ["agent"] = $"aauth:level{i}@x.example", ["act"] = innerAct };
        }
        var topAct = new JsonObject { ["agent"] = "aauth:up@x.example", ["act"] = innerAct };

        var headerObj = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-person.json", ["aud"] = Aud,
            ["agent"] = Agent, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["act"] = topAct,
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
        };
        var jwt = JwtWriter.SignCompact(headerObj, payloadObj, psKey);

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, psKey, Aud, agentKey, Agent));
    }

    [Fact(DisplayName = "§Auth Token Verification — MUST reject signature from different key")]
    public void Rejects_WrongSignatureKey()
    {
        var (jwt, _, agentKey) = GoodToken();
        var wrongPsKey = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifyAuthToken(jwt, wrongPsKey, Aud, agentKey, Agent));
    }
}
