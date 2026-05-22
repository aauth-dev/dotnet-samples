using System;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=hwk;jkt="..."</c> — the Pseudonymous signing mode.
/// The signing key's JWK thumbprint is used as the identifier.
/// </summary>
public sealed class HwkSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly IAAuthKey _key;
    private readonly string _header;

    public HwkSignatureKeyProvider(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        _header = SignatureKeyHeader.FormatHwk(key.ComputeJwkThumbprint());
    }

    public string GetSignatureKeyHeader() => _header;
}
