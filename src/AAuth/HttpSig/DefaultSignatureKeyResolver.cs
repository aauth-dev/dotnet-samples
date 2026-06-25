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

    /// <summary>Create the resolver.</summary>
    /// <param name="jwksClient">Required for the <c>jwks_uri</c> scheme. The <c>jkt-jwt</c> scheme is self-anchored (draft-05 §3.4) and needs no external client.</param>
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
            AAuthConstants.Schemes.Jwt => ResolveJwt(info),
            AAuthConstants.Schemes.Hwk => await ResolveHwkAsync(info, ct).ConfigureAwait(false),
            AAuthConstants.Schemes.JwksUri => await ResolveJwksUriAsync(info, ct).ConfigureAwait(false),
            AAuthConstants.Schemes.JktJwt => await ResolveJktJwtAsync(info, ct).ConfigureAwait(false),
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

    private static Task<IAAuthKey> ResolveJktJwtAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        // Self-anchored TOFU verification per draft-hardt-httpbis-signature-key-05
        // §3.4. The durable (enclave) key is embedded in the naming JWT's header
        // jwk; the issuer is that key's own thumbprint URI. No external lookup.
        if (info.Jwt is null || info.Header is null || info.Payload is null)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT could not be parsed.");

        // §3.4 step 2: check the typ header.
        var typ = (string?)info.Header["typ"];
        if (typ != AAuthConstants.TokenTypes.JktS256Jwt)
            throw new AAuthVerificationException(
                $"Signature-Key jkt-jwt scheme: unsupported naming JWT typ '{typ}' (expected '{AAuthConstants.TokenTypes.JktS256Jwt}').");

        // §3.4 step 4: extract the durable key from the header jwk.
        if (info.Header["jwk"] is not JsonObject durableJwk)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT header is missing the durable 'jwk'.");
        var durableKey = Crypto.KeyFactory.TryFromJwk(durableJwk)
            ?? throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT header 'jwk' is not a valid key.");

        // §3.4 steps 5-7: compute the durable thumbprint, build the expected
        // urn:jkt:sha-256: issuer, and compare to the iss claim by string equality.
        var expectedIss = AAuthConstants.JktThumbprintUrnPrefix + durableKey.ComputeJwkThumbprint();
        var iss = (string?)info.Payload["iss"];
        if (!string.Equals(iss, expectedIss, StringComparison.Ordinal))
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT 'iss' does not match the thumbprint of the header 'jwk'.");

        // §3.4 step 8: verify the naming JWT signature using the header jwk.
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
                "Signature-Key jkt-jwt scheme: naming JWT signature verification failed against the header durable key.");

        // §3.4 step 9 (exp/iat) is enforced by the verification middleware
        // (clock-skew-aware). §3.4 step 10: extract the ephemeral key from cnf.jwk.
        if (info.ConfirmationKey is null)
            throw new AAuthVerificationException(
                "Signature-Key jkt-jwt scheme: naming JWT does not contain cnf.jwk.");

        // §3.4 step 11: the ephemeral key verifies the HTTP message signature.
        return Task.FromResult(info.ConfirmationKey);
    }

    private static bool IsLoopback(Uri uri)
    {
        return uri.Host is "localhost" or "127.0.0.1" or "::1"
            || uri.Host.Equals("[::1]", StringComparison.OrdinalIgnoreCase);
    }
}
