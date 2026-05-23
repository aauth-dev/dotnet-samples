using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;

namespace AAuth.HttpSig;

/// <summary>
/// Default implementation of <see cref="ISignatureKeyResolver"/> that dispatches
/// on the Signature-Key scheme to resolve the public key for verification.
/// </summary>
public sealed class DefaultSignatureKeyResolver : ISignatureKeyResolver
{
    private readonly JwksClient? _jwksClient;

    /// <summary>Create the resolver.</summary>
    /// <param name="jwksClient">Required for <c>jwks_uri</c> scheme resolution.</param>
    public DefaultSignatureKeyResolver(JwksClient? jwksClient = null)
    {
        _jwksClient = jwksClient;
    }

    public async Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(info);

        IAAuthKey key = info.Scheme switch
        {
            "jwt" => ResolveJwt(info),
            "hwk" => await ResolveHwkAsync(info, ct).ConfigureAwait(false),
            "jwks_uri" => await ResolveJwksUriAsync(info, ct).ConfigureAwait(false),
            "jkt-jwt" => ResolveJktJwt(info),
            _ => throw new AAuthVerificationException($"Unsupported Signature-Key scheme: '{info.Scheme}'."),
        };

        return new SignatureKeyResolution { PublicKey = key, Info = info };
    }

    private static IAAuthKey ResolveJwt(SignatureKeyParser.ParsedSignatureKeyInfo info)
    {
        if (info.ConfirmationKey is null)
            throw new AAuthVerificationException("Signature-Key jwt scheme: cnf.jwk could not be extracted.");
        return info.ConfirmationKey;
    }

    private Task<IAAuthKey> ResolveHwkAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        // Per spec: hwk is an "inline public key" scheme — the key is carried
        // in the Signature-Key header itself. No external lookup required.
        if (info.ConfirmationKey is null)
            throw new AAuthVerificationException("Signature-Key hwk scheme: inline jwk could not be extracted.");

        return Task.FromResult<IAAuthKey>(info.ConfirmationKey);
    }

    private async Task<IAAuthKey> ResolveJwksUriAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(info.JwksUri))
            throw new AAuthVerificationException("Signature-Key jwks_uri scheme: missing uri.");
        if (string.IsNullOrEmpty(info.Kid))
            throw new AAuthVerificationException("Signature-Key jwks_uri scheme: missing kid.");

        if (_jwksClient is null)
            throw new AAuthVerificationException(
                "Signature-Key jwks_uri scheme received but no JwksClient is registered.");

        var uri = new Uri(info.JwksUri, UriKind.Absolute);

        // Enforce https (or loopback for dev)
        if (uri.Scheme != "https" && !IsLoopback(uri))
            throw new AAuthVerificationException(
                $"Signature-Key jwks_uri scheme: URI must use https (got '{uri.Scheme}').");

        var key = await _jwksClient.ResolveKeyAsync(uri, info.Kid, ct).ConfigureAwait(false);
        if (key is null)
            throw new AAuthVerificationException(
                $"Signature-Key jwks_uri scheme: key not found (kid={info.Kid}) at {info.JwksUri}.");

        return key;
    }

    private static IAAuthKey ResolveJktJwt(SignatureKeyParser.ParsedSignatureKeyInfo info)
    {
        if (string.IsNullOrEmpty(info.Jkt))
            throw new AAuthVerificationException("Signature-Key jkt-jwt scheme: missing jkt.");
        if (info.ConfirmationKey is null)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT does not contain cnf.jwk.");

        // The naming JWT's cnf.jwk is the ephemeral key. Its thumbprint must
        // match the jkt parameter — confirming the naming JWT delegates to this
        // specific ephemeral key.
        var keyThumbprint = info.ConfirmationKey.ComputeJwkThumbprint();
        if (!string.Equals(keyThumbprint, info.Jkt, StringComparison.Ordinal))
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: jkt parameter does not match cnf.jwk thumbprint.");

        // TODO: Full verification of the naming JWT signature against the durable
        // key (requires JWKS lookup of the durable key's issuer). For now, we trust
        // the structural binding — the middleware caller can layer JWT verification.
        return info.ConfirmationKey;
    }

    private static bool IsLoopback(Uri uri)
    {
        return uri.Host is "localhost" or "127.0.0.1" or "::1"
            || uri.Host.Equals("[::1]", StringComparison.OrdinalIgnoreCase);
    }
}
