using System;
using System.Text.Json;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// Produces an inline public JWK using standard hwk parameters.
/// </summary>
public sealed class HwkSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly string _header;

    public HwkSignatureKeyProvider(IAAuthKey key, string label = "sig")
    {
        ArgumentNullException.ThrowIfNull(key);
        _header = SignatureKeyHeader.FormatHwk(key, label);
    }

    public string GetSignatureKeyHeader() => _header;
}
