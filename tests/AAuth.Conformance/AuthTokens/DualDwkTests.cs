using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Conformance tests for dual-dwk acceptance per §Auth Token dwk rules.
/// The verifier must accept <c>aauth-person.json</c> or <c>aauth-access.json</c>
/// and reject other values when in dual-dwk mode.
/// </summary>
public class DualDwkTests
{
    private const string Iss = "https://ps.example";
    private const string Aud = "https://resource.example";
    private const string Kid = "ps-1";

    private static async Task<(string Jwt, AAuthKey PsKey, AAuthKey AgentKey)> BuildWithDwkAsync(string dwk)
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = await new AuthTokenBuilder
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
            Dwk = dwk,
        }.BuildAsync();
        return (jwt, psKey, agentKey);
    }

    [Fact(DisplayName = "§Auth Token dwk — verifier accepts aauth-person.json")]
    public async Task Accepts_PersonDwk()
    {
        var (jwt, psKey, agentKey) = await BuildWithDwkAsync(AuthTokenBuilder.PersonDwk);
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        // Dual-dwk mode: expectedDwk=null
        var result = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: null);
        Assert.Equal("aauth-person.json", (string?)result.Payload["dwk"]);
    }

    [Fact(DisplayName = "§Auth Token dwk — verifier accepts aauth-access.json")]
    public async Task Accepts_AccessDwk()
    {
        var (jwt, psKey, agentKey) = await BuildWithDwkAsync(AuthTokenBuilder.AccessDwk);
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var result = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: null);
        Assert.Equal("aauth-access.json", (string?)result.Payload["dwk"]);
    }

    [Fact(DisplayName = "§Auth Token dwk — expected aauth-access.json rejects aauth-person.json")]
    public async Task ExpectedAccessDwk_RejectsPersonDwk()
    {
        var (jwt, psKey, agentKey) = await BuildWithDwkAsync(AuthTokenBuilder.PersonDwk);
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };

        var exception = Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: AuthTokenBuilder.AccessDwk));

        Assert.Contains("dwk", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token dwk — verifier rejects aauth-resource.json as dwk for auth tokens")]
    public async Task Rejects_ResourceDwk()
    {
        // Manually craft a token with invalid dwk.
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "Ed25519", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-resource.json", ["aud"] = Aud,
            ["ps"] = Iss, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
        };
        var jwt = await JwtWriter.SignCompactAsync(headerObj, payloadObj, psKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: null));
    }

    [Fact(DisplayName = "§Auth Token dwk — verifier rejects aauth-agent.json as dwk")]
    public async Task Rejects_AgentDwk()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = iat + 3600;
        var headerObj = new JsonObject { ["alg"] = "Ed25519", ["typ"] = "aa-auth+jwt", ["kid"] = Kid };
        var payloadObj = new JsonObject
        {
            ["iss"] = Iss, ["dwk"] = "aauth-agent.json", ["aud"] = Aud,
            ["ps"] = Iss, ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["sub"] = "x", ["iat"] = iat, ["exp"] = exp, ["jti"] = "t1",
        };
        var jwt = await JwtWriter.SignCompactAsync(headerObj, payloadObj, psKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey, expectedDwk: null));
    }
}
