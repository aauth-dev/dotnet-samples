using System.Collections.Generic;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for Signature-Key header scheme support per §4.
/// </summary>
public class SignatureKeySchemesTests
{
    [Fact(DisplayName = "§4 — jwt scheme formats correctly")]
    public void JwtScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJwt("eyJ.payload.sig");
        Assert.Equal("sig=jwt;jwt=\"eyJ.payload.sig\"", header);
    }

    [Fact(DisplayName = "§4 — hwk scheme formats with jkt and inline jwk parameters")]
    public void HwkScheme_FormatsCorrectly()
    {
        var key = AAuthKey.Generate();
        var jkt = key.ComputeJwkThumbprint();
        var jwkJson = System.Text.Json.JsonSerializer.Serialize(key.ToPublicJwk());
        var jwkB64 = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(jwkJson);
        var header = SignatureKeyHeader.FormatHwk(jkt, jwkB64);
        Assert.StartsWith("sig=hwk;jkt=\"", header);
        Assert.Contains(";jwk=\"", header);
    }

    [Fact(DisplayName = "§4 — jwks_uri scheme formats with uri and kid parameters")]
    public void JwksUriScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJwksUri("https://example.com/.well-known/jwks.json", "key-1");
        Assert.Equal("sig=jwks_uri;uri=\"https://example.com/.well-known/jwks.json\";kid=\"key-1\"", header);
    }

    [Fact(DisplayName = "§4 — jkt-jwt scheme formats with jkt and jwt parameters")]
    public void JktJwtScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJktJwt("thumbprint123", "eyJ.payload.sig");
        Assert.Equal("sig=jkt-jwt;jkt=\"thumbprint123\";jwt=\"eyJ.payload.sig\"", header);
    }

    [Fact(DisplayName = "§4 — ParseAny handles jwt scheme")]
    public void ParseAny_JwtScheme()
    {
        // Build a minimal valid JWT with cnf.jwk
        var key = AAuthKey.Generate();
        var agentToken = new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            Key = key,
            KeyId = "k1",
            PersonServer = "https://ps.example",
        }.Build();
        var headerValue = SignatureKeyHeader.FormatJwt(agentToken);

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jwt", info.Scheme);
        Assert.NotNull(info.ConfirmationKey);
        Assert.NotNull(info.Jwt);
        Assert.NotNull(info.Payload);
    }

    [Fact(DisplayName = "§4 — ParseAny handles hwk scheme with inline key")]
    public void ParseAny_HwkScheme()
    {
        var key = AAuthKey.Generate();
        var provider = new HwkSignatureKeyProvider(key);
        var headerValue = provider.GetSignatureKeyHeader();

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("hwk", info.Scheme);
        Assert.Equal(key.ComputeJwkThumbprint(), info.Jkt);
        Assert.NotNull(info.ConfirmationKey); // Inline per spec
        Assert.Equal(key.ComputeJwkThumbprint(), info.ConfirmationKey.ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "§4 — ParseAny handles jwks_uri scheme")]
    public void ParseAny_JwksUriScheme()
    {
        var headerValue = SignatureKeyHeader.FormatJwksUri("https://example.com/jwks", "kid1");

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jwks_uri", info.Scheme);
        Assert.Equal("https://example.com/jwks", info.JwksUri);
        Assert.Equal("kid1", info.Kid);
    }

    [Fact(DisplayName = "§4 — ParseAny handles jkt-jwt scheme")]
    public void ParseAny_JktJwtScheme()
    {
        var key = AAuthKey.Generate();
        var agentToken = new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            Key = key,
            KeyId = "k1",
            PersonServer = "https://ps.example",
        }.Build();
        var jkt = key.ComputeJwkThumbprint();
        var headerValue = SignatureKeyHeader.FormatJktJwt(jkt, agentToken);

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jkt-jwt", info.Scheme);
        Assert.Equal(jkt, info.Jkt);
        Assert.NotNull(info.Jwt);
        Assert.NotNull(info.Payload);
    }
}
