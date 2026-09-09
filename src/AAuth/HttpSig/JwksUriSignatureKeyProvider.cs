using System;

namespace AAuth.HttpSig;

/// <summary>
/// Identifies a server and its metadata document for JWKS discovery.
/// </summary>
public sealed class JwksUriSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly string _header;

    public JwksUriSignatureKeyProvider(string id, string dwk, string kid, string label = "sig")
    {
        _header = SignatureKeyHeader.FormatJwksUri(id, dwk, kid, label);
    }

    public string GetSignatureKeyHeader() => _header;
}
