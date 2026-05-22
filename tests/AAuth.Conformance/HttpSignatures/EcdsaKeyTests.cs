using System.Text.Json.Nodes;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for ECDSA P-256 key (ES256) per §3 (Signature Algorithms).
/// </summary>
public class EcdsaKeyTests
{
    [Fact(DisplayName = "§3 — ES256 key generation produces valid key pair")]
    public void Generate_ProducesKeyPair()
    {
        var key = EcdsaAAuthKey.Generate();
        Assert.True(key.HasPrivateKey);
        Assert.Equal("ES256", key.Algorithm);
    }

    [Fact(DisplayName = "§3 — ES256 sign and verify round-trip")]
    public void SignAndVerify_RoundTrip()
    {
        var key = EcdsaAAuthKey.Generate();
        var data = "hello world"u8.ToArray();
        var signature = key.Sign(data);
        Assert.True(key.Verify(data, signature));
    }

    [Fact(DisplayName = "§3 — ES256 signature is deterministic (RFC 6979)")]
    public void Sign_IsDeterministic()
    {
        var key = EcdsaAAuthKey.Generate();
        var data = "deterministic test"u8.ToArray();
        var sig1 = key.Sign(data);
        var sig2 = key.Sign(data);
        Assert.Equal(sig1, sig2);
    }

    [Fact(DisplayName = "§3 — ES256 signature is 64 bytes (r||s fixed-length)")]
    public void Signature_Is64Bytes()
    {
        var key = EcdsaAAuthKey.Generate();
        var sig = key.Sign("test"u8.ToArray());
        Assert.Equal(64, sig.Length);
    }

    [Fact(DisplayName = "§3 — ES256 verification rejects tampered data")]
    public void Verify_RejectsTamperedData()
    {
        var key = EcdsaAAuthKey.Generate();
        var data = "original"u8.ToArray();
        var sig = key.Sign(data);
        var tampered = "modified"u8.ToArray();
        Assert.False(key.Verify(tampered, sig));
    }

    [Fact(DisplayName = "§3 — ES256 public JWK has correct structure")]
    public void PublicJwk_HasCorrectStructure()
    {
        var key = EcdsaAAuthKey.Generate();
        var jwk = key.ToPublicJwk();
        Assert.Equal("EC", (string?)jwk["kty"]);
        Assert.Equal("P-256", (string?)jwk["crv"]);
        Assert.NotNull(jwk["x"]);
        Assert.NotNull(jwk["y"]);
        Assert.Null(jwk["d"]); // No private key
    }

    [Fact(DisplayName = "§3 — ES256 private JWK includes 'd' parameter")]
    public void PrivateJwk_IncludesD()
    {
        var key = EcdsaAAuthKey.Generate();
        var jwk = key.ToPrivateJwk();
        Assert.NotNull(jwk["d"]);
    }

    [Fact(DisplayName = "§3 — ES256 JWK round-trip preserves key")]
    public void FromJwk_RoundTrip()
    {
        var original = EcdsaAAuthKey.Generate();
        var jwk = original.ToPrivateJwk();
        var restored = EcdsaAAuthKey.FromJwk(jwk);

        var data = "round-trip"u8.ToArray();
        var sig = original.Sign(data);
        Assert.True(restored.Verify(data, sig));
    }

    [Fact(DisplayName = "§3 — ES256 JWK thumbprint is consistent")]
    public void JwkThumbprint_IsConsistent()
    {
        var key = EcdsaAAuthKey.Generate();
        var t1 = key.ComputeJwkThumbprint();
        var t2 = key.ComputeJwkThumbprint();
        Assert.Equal(t1, t2);
        Assert.NotEmpty(t1);
    }

    [Fact(DisplayName = "§3 — IAAuthKey interface is implemented by both key types")]
    public void InterfaceImplementation()
    {
        IAAuthKey ed = AAuthKey.Generate();
        IAAuthKey ec = EcdsaAAuthKey.Generate();
        Assert.Equal("EdDSA", ed.Algorithm);
        Assert.Equal("ES256", ec.Algorithm);
    }
}
