using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AgentTokens;

/// <summary>
/// Receiver-side conformance for an <c>aa-agent+jwt</c> per
/// draft-hardt-oauth-aauth-protocol-01 §Agent Token Verification.
/// </summary>
/// <remarks>
/// These tests exercise <see cref="TokenVerifier"/> and
/// <see cref="SignatureKeyParser"/> from a verifier's point of view — every
/// MUST-reject clause in §Agent Token Verification is encoded as a failing
/// path expected to throw.
/// </remarks>
public class AgentTokenVerificationTests
{
    private const string Iss = "https://ap.example";
    private const string Sub = "aauth:alice@ap.example";
    private const string Kid = "k1";

    private static string GoodToken(AAuthKey key) => new AgentTokenBuilder
    {
        Issuer = Iss,
        Subject = Sub,
        KeyId = Kid,
        Key = key,
    }.Build();

    /// <summary>
    /// "Verifiers MUST verify the JWS signature using the key from cnf.jwk."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — accepts well-formed token signed by cnf.jwk")]
    public void HappyPath_Verifies()
    {
        var key = AAuthKey.Generate();
        var jwt = GoodToken(key);
        var verifier = new TokenVerifier();

        var verified = verifier.VerifySelfIssuedAgentToken(jwt, key);

        Assert.Equal(AgentTokenBuilder.TokenType, verified.TokenType);
    }

    /// <summary>
    /// "Verifiers MUST reject tokens whose alg header is 'none'."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject alg=none")]
    public void Rejects_AlgNone()
    {
        var key = AAuthKey.Generate();
        var header = "{\"alg\":\"none\",\"typ\":\"aa-agent+jwt\",\"kid\":\"k\"}";
        var payload = $"{{\"iss\":\"{Iss}\",\"dwk\":\"aauth-agent.json\",\"sub\":\"x\",\"cnf\":{{\"jwk\":{key.ToPublicJwk().ToJsonString()}}},\"iat\":1,\"exp\":9999999999}}";
        var jwt = $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(payload)}.AAAA";

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifySelfIssuedAgentToken(jwt, key));
    }

    /// <summary>
    /// "Verifiers MUST reject expired tokens."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject expired tokens")]
    public void Rejects_Expired()
    {
        var key = AAuthKey.Generate();
        var issued = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var jwt = new AgentTokenBuilder
        {
            Issuer = Iss,
            Subject = Sub,
            KeyId = Kid,
            Key = key,
            IssuedAt = issued,
            Lifetime = TimeSpan.FromSeconds(1),
        }.Build();

        var verifier = new TokenVerifier { Clock = () => issued.AddHours(1) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, key));
    }

    /// <summary>
    /// "Verifiers MUST reject tokens whose typ is not 'aa-agent+jwt'."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject wrong typ")]
    public void Rejects_WrongTyp()
    {
        var key = AAuthKey.Generate();
        var jwt = GoodToken(key);
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().Verify(jwt, key, "aa-resource+jwt", "aauth-agent.json"));
    }

    /// <summary>
    /// "Verifiers MUST reject tokens with a missing or unexpected dwk claim."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject wrong dwk")]
    public void Rejects_WrongDwk()
    {
        var key = AAuthKey.Generate();
        var jwt = GoodToken(key);
        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().Verify(jwt, key, AgentTokenBuilder.TokenType, "aauth-person.json"));
    }

    /// <summary>
    /// "Verifiers MUST verify the JWS signature using the key from cnf.jwk."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject signatures from a different key")]
    public void Rejects_WrongSignatureKey()
    {
        var a = AAuthKey.Generate();
        var b = AAuthKey.Generate();
        var jwt = GoodToken(a);

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifySelfIssuedAgentToken(jwt, b));
    }

    /// <summary>
    /// "Verifiers MUST reject tokens whose payload cannot be parsed as JSON."
    /// </summary>
    [Fact(DisplayName = "§Agent Token Verification — MUST reject malformed payload")]
    public void Rejects_MalformedPayload()
    {
        var key = AAuthKey.Generate();
        var header = "{\"alg\":\"EdDSA\",\"typ\":\"aa-agent+jwt\",\"kid\":\"k\"}";
        var jwt = $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode("not-json")}.AAAA";

        Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier().VerifySelfIssuedAgentToken(jwt, key));
    }
}
