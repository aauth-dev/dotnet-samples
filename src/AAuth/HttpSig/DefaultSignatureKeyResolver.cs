using System;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// Default implementation of <see cref="ISignatureKeyResolver"/> that dispatches
/// on the Signature-Key scheme to resolve the public key for verification.
/// </summary>
public sealed class DefaultSignatureKeyResolver : ISignatureKeyResolver
{
    private readonly JwksClient? _jwksClient;
    private readonly MetadataClient? _metadataClient;

    /// <summary>Create the resolver.</summary>
    /// <param name="jwksClient">Required for <c>jwks_uri</c> and <c>jkt-jwt</c> scheme resolution.</param>
    /// <param name="metadataClient">Required for <c>jkt-jwt</c> naming JWT issuer verification.</param>
    public DefaultSignatureKeyResolver(JwksClient? jwksClient = null, MetadataClient? metadataClient = null)
    {
        _jwksClient = jwksClient;
        _metadataClient = metadataClient;
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
            "jkt-jwt" => await ResolveJktJwtAsync(info, ct).ConfigureAwait(false),
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

    private async Task<IAAuthKey> ResolveJktJwtAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
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

        // Verify the naming JWT signature against the issuer's durable key.
        if (info.Jwt is null || info.Header is null || info.Payload is null)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT could not be parsed.");

        var iss = (string?)info.Payload["iss"];
        if (string.IsNullOrEmpty(iss) || !AAuthUrl.IsHttpsOrLoopback(iss))
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT 'iss' must be an absolute https:// URL (or http://localhost).");

        // Validate expiration — an expired naming JWT must not be trusted.
        var expNode = info.Payload["exp"];
        if (expNode is not null)
        {
            var exp = DateTimeOffset.FromUnixTimeSeconds(expNode.GetValue<long>());
            if (exp < DateTimeOffset.UtcNow)
                throw new AAuthVerificationException(
                    "Signature-Key jkt-jwt scheme: naming JWT has expired.");
        }

        var kid = (string?)info.Header["kid"];
        if (string.IsNullOrEmpty(kid))
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT header is missing 'kid'.");

        // Fetch issuer metadata to find JWKS endpoint.
        if (_jwksClient is null || _metadataClient is null)
        {
            // Graceful fallback: if we don't have metadata/JWKS clients, trust
            // the structural binding only (same as previous behavior).
            return info.ConfirmationKey;
        }

        var metadataUrl = MetadataClient.BuildUrl(iss, AgentTokenBuilder.AgentDwk);
        JsonObject metadataDoc;
        try
        {
            metadataDoc = await _metadataClient.FetchAsync(metadataUrl, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new AAuthVerificationException(
                $"Signature-Key jkt-jwt scheme: failed to fetch issuer metadata from {metadataUrl}.", ex);
        }

        var jwksUriRaw = (string?)metadataDoc["jwks_uri"];
        if (string.IsNullOrEmpty(jwksUriRaw) || !Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
            throw new AAuthVerificationException(
                $"Signature-Key jkt-jwt scheme: issuer metadata 'jwks_uri' is missing or invalid.");
        if (!AAuthUrl.IsHttpsOrLoopback(jwksUriRaw))
            throw new AAuthVerificationException(
                $"Signature-Key jkt-jwt scheme: jwks_uri must be https (or http://localhost).");

        var durableKey = await _jwksClient.ResolveKeyAsync(jwksUri, kid, ct).ConfigureAwait(false);
        if (durableKey is null)
            throw new AAuthVerificationException(
                $"Signature-Key jkt-jwt scheme: no key with kid '{kid}' at {jwksUri}.");

        // Verify the naming JWT signature against the durable key.
        var segments = info.Jwt.Split('.');
        if (segments.Length != 3)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT is not a compact JWS.");

        byte[] signature;
        try
        {
            signature = Base64UrlEncoder.DecodeBytes(segments[2]);
        }
        catch (Exception)
        {
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT signature is not valid base64url.");
        }

        var signingInput = Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]);
        if (!durableKey.Verify(signingInput, signature))
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT signature verification failed against issuer's durable key.");

        return info.ConfirmationKey;
    }

    private static bool IsLoopback(Uri uri)
    {
        return uri.Host is "localhost" or "127.0.0.1" or "::1"
            || uri.Host.Equals("[::1]", StringComparison.OrdinalIgnoreCase);
    }
}
