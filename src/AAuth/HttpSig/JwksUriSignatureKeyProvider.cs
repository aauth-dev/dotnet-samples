using System;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=jwks_uri;uri="...";kid="..."</c> — the Agent Identity signing mode.
/// The verifier fetches the JWKS from the URI and resolves the key by kid.
/// </summary>
public sealed class JwksUriSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly string _header;

    public JwksUriSignatureKeyProvider(string uri, string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);
        ArgumentException.ThrowIfNullOrEmpty(kid);
        _header = SignatureKeyHeader.FormatJwksUri(uri, kid);
    }

    public string GetSignatureKeyHeader() => _header;
}
