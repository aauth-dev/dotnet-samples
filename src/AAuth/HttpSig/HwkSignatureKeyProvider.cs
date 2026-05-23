using System;
using System.Text.Json;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=hwk;jkt="...";jwk="..."</c> — the Pseudonymous signing mode.
/// The full public key is included inline (base64url-encoded JWK JSON) per the spec's
/// requirement that hwk is an "inline public key" scheme.
/// </summary>
public sealed class HwkSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly IAAuthKey _key;
    private readonly string _header;

    public HwkSignatureKeyProvider(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        var jkt = key.ComputeJwkThumbprint();
        var jwkJson = JsonSerializer.Serialize(key.ToPublicJwk());
        var jwkBase64Url = Base64UrlEncoder.Encode(jwkJson);
        _header = SignatureKeyHeader.FormatHwk(jkt, jwkBase64Url);
    }

    public string GetSignatureKeyHeader() => _header;
}
