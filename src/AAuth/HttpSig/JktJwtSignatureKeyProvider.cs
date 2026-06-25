using System;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Produces <c>Signature-Key: sig=jkt-jwt;jwt="..."</c> — the self-issued
/// two-key delegation signing mode (<c>draft-hardt-httpbis-signature-key-05</c>
/// §3.4). The HTTP message signature is made with the ephemeral key (held by the
/// signing handler); the naming JWT supplied here (signed by the durable key)
/// embeds the durable public key and names the ephemeral key via <c>cnf.jwk</c>.
/// </summary>
public sealed class JktJwtSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly Func<string> _namingJwtFactory;

    /// <summary>Create the provider.</summary>
    /// <param name="namingJwtFactory">Supplies the current <c>jkt-s256+jwt</c> delegation JWT (regenerated per request as needed).</param>
    public JktJwtSignatureKeyProvider(Func<string> namingJwtFactory)
    {
        ArgumentNullException.ThrowIfNull(namingJwtFactory);
        _namingJwtFactory = namingJwtFactory;
    }

    public string GetSignatureKeyHeader()
    {
        return SignatureKeyHeader.FormatJktJwt(_namingJwtFactory());
    }
}
