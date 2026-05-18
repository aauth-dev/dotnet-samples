using System;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class SignatureKeyParserTests
{
    [Fact]
    public void Parse_ExtractsConfirmationKeyFromAgentJwt()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = key,
        }.Build();

        var headerValue = SignatureKeyHeader.FormatJwt(jwt);
        var parsed = SignatureKeyParser.Parse(headerValue);

        Assert.Equal(jwt, parsed.Jwt);
        Assert.Equal(key.ComputeJwkThumbprint(), parsed.ConfirmationKey.ComputeJwkThumbprint());
    }

    [Fact]
    public void Parse_RejectsNonJwtScheme()
    {
        Assert.Throws<AAuthVerificationException>(() =>
            SignatureKeyParser.Parse("sig=hwk;jwk=\"{}\""));
    }

    [Fact]
    public void Parse_RejectsMalformedJwt()
    {
        Assert.Throws<AAuthVerificationException>(() =>
            SignatureKeyParser.Parse("sig=jwt;jwt=\"not-a-jwt\""));
    }

    [Fact]
    public void Parse_RejectsMissingCnf()
    {
        // Hand-build a JWT with no cnf claim — payload is just iss/sub.
        var header = "{\"alg\":\"EdDSA\",\"typ\":\"aa-agent+jwt\"}";
        var payload = "{\"iss\":\"https://x\",\"sub\":\"y\"}";
        var encodedHeader = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(header);
        var encodedPayload = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payload);
        var bogusJwt = $"{encodedHeader}.{encodedPayload}.AAAA";

        Assert.Throws<AAuthVerificationException>(() =>
            SignatureKeyParser.Parse(SignatureKeyHeader.FormatJwt(bogusJwt)));
    }
}
