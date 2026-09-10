using System.Security.Cryptography;
using System.Text;
using AAuth.Crypto;
using AAuth.Errors;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tests.HttpSig;

public class JwkV10Tests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExportImportRetainsAlgorithmCryptoAndRfc7638Thumbprint(bool ecdsa)
    {
        IAAuthKey original = ecdsa ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();
        var jwk = original.ToPublicJwk();
        Assert.Equal(ecdsa ? "ES256" : "Ed25519", (string?)jwk["alg"]);
        var imported = KeyFactory.FromPublicJwk(jwk);
        Assert.True(imported.Verify("wire"u8.ToArray(), original.Sign("wire"u8.ToArray())));
        var canonical = ecdsa
            ? $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{jwk["x"]}\",\"y\":\"{jwk["y"]}\"}}"
            : $"{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{jwk["x"]}\"}}";
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))), imported.ComputeJwkThumbprint());
        Assert.Throws<JwkValidationException>(() => KeyFactory.FromPublicJwk(original.ToPrivateJwk()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("EdDSA")]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    [InlineData("RS1")]
    [InlineData("ML-DSA-65")]
    public void UnsupportedAlgorithmIsTyped(string? algorithm)
    {
        var jwk = AAuthKey.Generate().ToPublicJwk();
        if (algorithm is null) jwk.Remove("alg"); else jwk["alg"] = algorithm;
        Assert.Equal(SignatureErrorCode.UnsupportedAlgorithm, Assert.Throws<JwkValidationException>(() => KeyFactory.FromPublicJwk(jwk)).Code);
    }

    [Theory]
    [InlineData("kty", "EC")]
    [InlineData("crv", "Ed448")]
    [InlineData("x", "AA")]
    public void InvalidKeyIsTyped(string member, string value)
    {
        var jwk = AAuthKey.Generate().ToPublicJwk();
        jwk[member] = value;
        Assert.Equal(SignatureErrorCode.InvalidKey, Assert.Throws<JwkValidationException>(() => KeyFactory.FromPublicJwk(jwk)).Code);
    }
}