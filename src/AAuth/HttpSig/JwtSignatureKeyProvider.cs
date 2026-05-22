using System;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=jwt;jwt="..."</c> — the Agent Token signing mode.
/// </summary>
public sealed class JwtSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly Func<string> _tokenFactory;

    public JwtSignatureKeyProvider(Func<string> tokenFactory)
    {
        ArgumentNullException.ThrowIfNull(tokenFactory);
        _tokenFactory = tokenFactory;
    }

    public string GetSignatureKeyHeader() => SignatureKeyHeader.FormatJwt(_tokenFactory());
}
