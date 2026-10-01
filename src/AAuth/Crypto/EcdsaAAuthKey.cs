using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace AAuth.Crypto;

/// <summary>
/// ECDSA P-256 key using RFC 6979 deterministic signatures via BouncyCastle's
/// <see cref="HMacDsaKCalculator"/>. Produces ES256-compatible JWTs.
/// </summary>
public sealed class EcdsaAAuthKey : IAAuthExportableKey
{
    /// <summary>The JOSE <c>alg</c> value.</summary>
    public const string Alg = "ES256";

    /// <summary>The JOSE <c>crv</c> value.</summary>
    public const string CurveName = "P-256";

    /// <summary>The JOSE <c>kty</c> value.</summary>
    public const string Kty = "EC";

    private static readonly X9ECParameters s_curve = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECDomainParameters s_domain = new(s_curve.Curve, s_curve.G, s_curve.N, s_curve.H);
    private static readonly SecureRandom s_random = new();

    private readonly ECPrivateKeyParameters? _private;
    private readonly ECPublicKeyParameters _public;

    private EcdsaAAuthKey(ECPrivateKeyParameters? priv, ECPublicKeyParameters pub)
    {
        _private = priv;
        _public = pub;
    }

    /// <inheritdoc/>
    public string Algorithm => Alg;

    /// <inheritdoc/>
    public bool HasPrivateKey => _private is not null;

    /// <summary>Generate a fresh P-256 key pair.</summary>
    public static EcdsaAAuthKey Generate()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("EC");
        gen.Init(new ECKeyGenerationParameters(s_domain, s_random));
        var pair = gen.GenerateKeyPair();
        return new EcdsaAAuthKey(
            (ECPrivateKeyParameters)pair.Private,
            (ECPublicKeyParameters)pair.Public);
    }

    /// <inheritdoc/>
    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Sign(data.ToArray()));

    /// <summary>Sign the given data synchronously with the local private key.</summary>
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (_private is null) throw new InvalidOperationException("Key has no private component.");

        // RFC 6979 deterministic k via HMacDsaKCalculator
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()));
        signer.Init(forSigning: true, _private);

        var hash = SHA256.HashData(data);
        var components = signer.GenerateSignature(hash);

        // Encode as fixed-length r||s (32 bytes each for P-256)
        return EncodeFixedRS(components[0], components[1], 32);
    }

    /// <inheritdoc/>
    public bool Verify(byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Length != 64) return false;

        var signer = new ECDsaSigner();
        signer.Init(forSigning: false, _public);

        var hash = SHA256.HashData(data);
        var r = new BigInteger(1, signature, 0, 32);
        var s = new BigInteger(1, signature, 32, 32);
        return signer.VerifySignature(hash, r, s);
    }

    /// <inheritdoc/>
    public JsonObject ToPublicJwk()
    {
        var point = _public.Q.Normalize();
        var x = point.AffineXCoord.GetEncoded();
        var y = point.AffineYCoord.GetEncoded();
        return new JsonObject
        {
            ["alg"] = Alg,
            ["kty"] = Kty,
            ["crv"] = CurveName,
            ["x"] = Base64UrlEncoder.Encode(x),
            ["y"] = Base64UrlEncoder.Encode(y),
        };
    }

    /// <inheritdoc/>
    public JsonObject ToPrivateJwk()
    {
        if (_private is null) throw new InvalidOperationException("Key has no private component.");
        var jwk = ToPublicJwk();
        var d = _private.D.ToByteArrayUnsigned();
        // Pad to 32 bytes
        if (d.Length < 32)
        {
            var padded = new byte[32];
            d.CopyTo(padded.AsSpan(32 - d.Length));
            d = padded;
        }
        jwk["d"] = Base64UrlEncoder.Encode(d);
        return jwk;
    }

    /// <inheritdoc/>
    public string ComputeJwkThumbprint()
    {
        var point = _public.Q.Normalize();
        var x = Base64UrlEncoder.Encode(point.AffineXCoord.GetEncoded());
        var y = Base64UrlEncoder.Encode(point.AffineYCoord.GetEncoded());
        // RFC 7638: members in lexicographic order for EC: crv, kty, x, y
        var canonical = $"{{\"crv\":\"{CurveName}\",\"kty\":\"{Kty}\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }

    /// <summary>Parse a P-256 JWK. Loads private half if <c>d</c> is present.</summary>
    public static EcdsaAAuthKey FromJwk(JsonObject jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        KeyFactory.Validate(jwk);
        if ((string?)jwk["kty"] != Kty || (string?)jwk["crv"] != CurveName)
            throw new ArgumentException($"JWK is not a P-256 EC key (kty={(string?)jwk["kty"]}, crv={(string?)jwk["crv"]}).", nameof(jwk));

        var x = KeyFactory.ReadCoordinate(jwk, "x");
        var y = KeyFactory.ReadCoordinate(jwk, "y");

        var point = s_curve.Curve.CreatePoint(
            new BigInteger(1, x),
            new BigInteger(1, y));
        var pub = new ECPublicKeyParameters(point, s_domain);

        ECPrivateKeyParameters? priv = null;
        if (jwk.ContainsKey("d"))
        {
            var dBytes = KeyFactory.ReadCoordinate(jwk, "d");
            priv = new ECPrivateKeyParameters(new BigInteger(1, dBytes), s_domain);
            if (!s_domain.G.Multiply(priv.D).Normalize().Equals(point.Normalize()))
                throw new ArgumentException("JWK public coordinates do not match private key.", nameof(jwk));
        }

        return new EcdsaAAuthKey(priv, pub);
    }

    private static byte[] EncodeFixedRS(BigInteger r, BigInteger s, int fieldSize)
    {
        var result = new byte[fieldSize * 2];
        var rBytes = r.ToByteArrayUnsigned();
        var sBytes = s.ToByteArrayUnsigned();
        rBytes.CopyTo(result.AsSpan(fieldSize - rBytes.Length));
        sBytes.CopyTo(result.AsSpan(fieldSize * 2 - sBytes.Length));
        return result;
    }
}
