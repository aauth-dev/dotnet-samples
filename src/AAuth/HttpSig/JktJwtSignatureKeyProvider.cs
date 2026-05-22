using System;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=jkt-jwt;jkt="...";jwt="..."</c> — the two-key
/// delegation signing mode. The HTTP signature is made with the ephemeral key;
/// a naming JWT (signed by the durable key) binds the ephemeral key's thumbprint.
/// </summary>
public sealed class JktJwtSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly IAAuthKey _ephemeralKey;
    private readonly Func<string> _namingJwtFactory;

    public JktJwtSignatureKeyProvider(IAAuthKey ephemeralKey, Func<string> namingJwtFactory)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(namingJwtFactory);
        _ephemeralKey = ephemeralKey;
        _namingJwtFactory = namingJwtFactory;
    }

    public string GetSignatureKeyHeader()
    {
        var jkt = _ephemeralKey.ComputeJwkThumbprint();
        var jwt = _namingJwtFactory();
        return SignatureKeyHeader.FormatJktJwt(jkt, jwt);
    }
}
