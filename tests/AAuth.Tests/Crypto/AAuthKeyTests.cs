using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests;

public class AAuthKeyTests
{
    [Fact]
    public void Generate_ProducesUsableKeyPair()
    {
        var key = AAuthKey.Generate();

        Assert.True(key.HasPrivateKey);
        Assert.Equal(32, key.PublicKeyBytes.Length);
        Assert.Equal(32, key.PrivateKeyBytes.Length);
    }

    [Fact]
    public void SignAndVerify_RoundTrip()
    {
        var key = AAuthKey.Generate();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        var sig = key.Sign(data);
        Assert.True(key.Verify(data, sig));

        // Tampered data fails verification.
        data[0] ^= 0xFF;
        Assert.False(key.Verify(data, sig));
    }

    [Fact]
    public void PublicJwk_HasExpectedShape()
    {
        var key = AAuthKey.Generate();
        var jwk = key.ToPublicJwk();

        Assert.Equal("OKP", (string?)jwk["kty"]);
        Assert.Equal("Ed25519", (string?)jwk["crv"]);
        Assert.False(string.IsNullOrEmpty((string?)jwk["x"]));
        Assert.Null(jwk["d"]);
    }

    [Fact]
    public void PrivateJwk_IncludesD()
    {
        var key = AAuthKey.Generate();
        var jwk = key.ToPrivateJwk();

        Assert.False(string.IsNullOrEmpty((string?)jwk["d"]));
    }

    [Fact]
    public void FromJwk_RoundTripsPublicAndPrivate()
    {
        var original = AAuthKey.Generate();

        var pub = AAuthKey.FromJwk(original.ToPublicJwk());
        Assert.False(pub.HasPrivateKey);
        Assert.Equal(original.PublicKeyBytes, pub.PublicKeyBytes);

        var priv = AAuthKey.FromJwk(original.ToPrivateJwk());
        Assert.True(priv.HasPrivateKey);
        Assert.Equal(original.PrivateKeyBytes, priv.PrivateKeyBytes);
        Assert.Equal(original.PublicKeyBytes, priv.PublicKeyBytes);
    }

    [Fact]
    public void Thumbprint_IsDeterministicAndCorrectLength()
    {
        var key = AAuthKey.Generate();

        var t1 = key.ComputeJwkThumbprint();
        var t2 = AAuthKey.FromJwk(key.ToPublicJwk()).ComputeJwkThumbprint();

        Assert.Equal(t1, t2);

        // base64url-encoded SHA-256 = 43 chars without padding.
        Assert.Equal(43, t1.Length);
    }

    [Fact]
    public void Thumbprint_MatchesRfc7638Vector()
    {
        // From RFC 8037 §A.3: thumbprint of an Ed25519 public key.
        // {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        var jwk = JsonNode.Parse("""
            {
              "kty": "OKP",
              "crv": "Ed25519",
              "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
            """)!.AsObject();
        var key = AAuthKey.FromJwk(jwk);

        Assert.Equal("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", key.ComputeJwkThumbprint());
    }

    [Fact]
    public void FromJwk_RejectsNonEd25519()
    {
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
        };
        Assert.Throws<ArgumentException>(() => AAuthKey.FromJwk(jwk));
    }

    [Fact]
    public void FromJwk_RejectsMismatchedXAndD()
    {
        // Take a real private JWK, then swap in a different 'x' so the
        // public/private halves disagree. FromJwk MUST reject this — otherwise
        // signed tokens won't verify against their own embedded cnf.jwk.
        var privateJwk = AAuthKey.Generate().ToPrivateJwk();
        privateJwk["x"] = Base64UrlEncoder.Encode(AAuthKey.Generate().PublicKeyBytes);

        Assert.Throws<ArgumentException>(() => AAuthKey.FromJwk(privateJwk));
    }
}
