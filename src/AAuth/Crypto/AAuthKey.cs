using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AAuth.Crypto;

/// <summary>
/// An Ed25519 key pair used for AAuth signing operations. Wraps BouncyCastle
/// because neither .NET 10 (on this runtime) nor <c>Microsoft.IdentityModel</c>
/// ships a usable EdDSA implementation yet.
/// </summary>
public sealed class AAuthKey
{
    /// <summary>The JOSE <c>alg</c> value for Ed25519.</summary>
    public const string Algorithm = "EdDSA";

    /// <summary>The JOSE <c>crv</c> value for Ed25519.</summary>
    public const string Curve = "Ed25519";

    /// <summary>The JOSE <c>kty</c> value for OKP keys.</summary>
    public const string KeyType = "OKP";

    private readonly Ed25519PrivateKeyParameters? _private;
    private readonly Ed25519PublicKeyParameters _public;

    private AAuthKey(Ed25519PrivateKeyParameters? privateKey, Ed25519PublicKeyParameters publicKey)
    {
        _private = privateKey;
        _public = publicKey;
    }

    /// <summary>True if this instance can sign (i.e. holds the private key).</summary>
    public bool HasPrivateKey => _private is not null;

    /// <summary>32-byte raw public key.</summary>
    public byte[] PublicKeyBytes => _public.GetEncoded();

    /// <summary>32-byte raw private seed. Throws when this instance is public-only.</summary>
    public byte[] PrivateKeyBytes =>
        _private?.GetEncoded() ?? throw new InvalidOperationException("Key has no private component.");

    /// <summary>Generate a fresh Ed25519 key pair.</summary>
    public static AAuthKey Generate()
    {
        var random = new SecureRandom();
        var priv = new Ed25519PrivateKeyParameters(random);
        var pub = priv.GeneratePublicKey();
        return new AAuthKey(priv, pub);
    }

    /// <summary>Sign the given data with the private key.</summary>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        if (_private is null)
        {
            throw new InvalidOperationException("Key has no private component.");
        }

        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(forSigning: true, _private);
        signer.BlockUpdate(data.ToArray(), 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Verify a signature with the public key.</summary>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(forSigning: false, _public);
        var dataArr = data.ToArray();
        signer.BlockUpdate(dataArr, 0, dataArr.Length);
        return signer.VerifySignature(signature.ToArray());
    }

    /// <summary>Export the public half as a JWK JSON document.</summary>
    public JsonObject ToPublicJwk() => new()
    {
        ["kty"] = KeyType,
        ["crv"] = Curve,
        ["x"] = Base64UrlEncoder.Encode(PublicKeyBytes),
    };

    /// <summary>Export both halves as a JWK JSON document (includes <c>d</c>).</summary>
    public JsonObject ToPrivateJwk()
    {
        if (_private is null)
        {
            throw new InvalidOperationException("Key has no private component.");
        }

        var jwk = ToPublicJwk();
        jwk["d"] = Base64UrlEncoder.Encode(PrivateKeyBytes);
        return jwk;
    }

    /// <summary>
    /// Compute the RFC 7638 JWK thumbprint of the public key, base64url-encoded
    /// (no padding). The canonical members for an OKP key are <c>crv</c>,
    /// <c>kty</c>, and <c>x</c> in lexicographic order.
    /// </summary>
    public string ComputeJwkThumbprint()
    {
        var canonical = JsonSerializer.Serialize(new
        {
            crv = Curve,
            kty = KeyType,
            x = Base64UrlEncoder.Encode(PublicKeyBytes),
        });
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }

    /// <summary>Parse a JWK JSON document. Loads the private half if <c>d</c> is present.</summary>
    public static AAuthKey FromJwk(JsonObject jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        if ((string?)jwk["kty"] != KeyType || (string?)jwk["crv"] != Curve)
        {
            throw new ArgumentException($"JWK is not an Ed25519 OKP key (kty={(string?)jwk["kty"]}, crv={(string?)jwk["crv"]}).", nameof(jwk));
        }

        var x = (string?)jwk["x"] ?? throw new ArgumentException("JWK missing 'x' parameter.", nameof(jwk));
        var publicBytes = Base64UrlEncoder.DecodeBytes(x);
        var pub = new Ed25519PublicKeyParameters(publicBytes, 0);

        Ed25519PrivateKeyParameters? priv = null;
        if (jwk["d"] is JsonValue dValue && dValue.TryGetValue<string>(out var d))
        {
            var privateBytes = Base64UrlEncoder.DecodeBytes(d);
            priv = new Ed25519PrivateKeyParameters(privateBytes, 0);
        }

        return new AAuthKey(priv, pub);
    }

    /// <summary>Parse a JWK from a JSON string.</summary>
    public static AAuthKey FromJwkJson(string json)
    {
        var node = JsonNode.Parse(json) as JsonObject
            ?? throw new ArgumentException("JWK JSON is not an object.", nameof(json));
        return FromJwk(node);
    }
}
