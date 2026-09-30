using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Signs each request as an issuer (<c>jwks_uri</c> scheme) with the key set's active
/// key at send time, so key rotation reaches outbound calls without a restart.
/// </summary>
internal sealed class AAuthSigningKeySetHandler(AAuthSigningKeySet keys, string issuer, string dwk) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var (kid, signer) = keys.Active;
        await new AAuthSigningHandler(signer, new JwksUriSignatureKeyProvider(issuer, dwk, kid))
            .SignAsync(request, cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
