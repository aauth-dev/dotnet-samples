using System;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using AAuth.Errors;
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
    private readonly TokenVerifier _tokenVerifier;
    private readonly IReadOnlyList<ISignatureTokenVerifier> _tokenVerifiers;

    /// <summary>Create the resolver.</summary>
    /// <param name="jwksClient">Required for the <c>jwks_uri</c> scheme. The <c>jkt-jwt</c> scheme is self-anchored (draft-05 §3.4) and needs no external client.</param>
    public DefaultSignatureKeyResolver(JwksClient? jwksClient = null, MetadataClient? metadataClient = null,
        TokenVerifier? tokenVerifier = null, IEnumerable<ISignatureTokenVerifier>? tokenVerifiers = null)
    {
        _jwksClient = jwksClient;
        _metadataClient = metadataClient;
        _tokenVerifier = tokenVerifier ?? new TokenVerifier { EgressPolicy = metadataClient?.Policy ?? AAuthEgressPolicy.Production };
        _tokenVerifiers = tokenVerifiers?.ToArray() ?? [];
    }

    internal DefaultSignatureKeyResolver WithValidation(JwksClient? jwks, MetadataClient? metadata, TokenVerifier verifier) =>
        new(jwks ?? _jwksClient, metadata ?? _metadataClient, verifier, _tokenVerifiers);

    public async Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(info);

        if (info.Scheme is "jwt" or "self-jwt")
            return await ResolveAssertionAsync(info, ct).ConfigureAwait(false);
        if (info.Scheme == "jkt-jwt")
        {
            var naming = NamingTokenVerifier.Verify(info.Jwt!, _tokenVerifier.Clock(), _tokenVerifier.ClockSkew);
            return new() { PublicKey = naming.ConfirmationKey, Info = WithKey(info, naming.ConfirmationKey, naming.DurableKey.ComputeJwkThumbprint()),
                DurableThumbprint = naming.DurableKey.ComputeJwkThumbprint(), KeyId = naming.ConfirmationKey.ComputeJwkThumbprint() };
        }
        IAAuthKey key = info.Scheme switch
        {
            AAuthConstants.Schemes.Hwk => await ResolveHwkAsync(info, ct).ConfigureAwait(false),
            AAuthConstants.Schemes.JwksUri => await ResolveJwksUriAsync(info, ct).ConfigureAwait(false),
            AAuthConstants.Schemes.Jwks => await ResolveDirectAsync(info.JwksUri!, info.Kid!, ct).ConfigureAwait(false),
            _ => throw new AAuthVerificationException(SignatureErrorCode.UnsupportedScheme, $"Unsupported Signature-Key scheme: '{info.Scheme}'."),
        };

        return new SignatureKeyResolution { PublicKey = key, Info = WithKey(info, key),
            VerifiedIdentifier = info.Identifier, KeyId = info.Kid ?? key.ComputeJwkThumbprint() };
    }

    private async Task<SignatureKeyResolution> ResolveAssertionAsync(SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        var typ = SignatureKeyParser.Text(info.Header, "typ");
        var companion = _tokenVerifiers.SingleOrDefault(verifier => verifier.Scheme == info.Scheme && verifier.TokenType == typ);
        var builtin = info.Scheme == "jwt" && typ is AgentTokenBuilder.TokenType or AuthTokenBuilder.TokenType;
        if (!builtin && companion is null)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected JWT typ for this signing scheme.");
        NamingTokenVerifier.ValidateTime(info.Payload!, _tokenVerifier.Clock(), _tokenVerifier.ClockSkew, requireIssuedAt: false);
        var issuer = SignatureKeyParser.Text(info.Payload, "iss")
            ?? throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires iss.");
        var dwk = SignatureKeyParser.Text(info.Payload, "dwk")
            ?? throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires dwk.");
        var kid = SignatureKeyParser.Text(info.Header, "kid")
            ?? throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires kid.");
        if (builtin && (typ == AgentTokenBuilder.TokenType && dwk != AgentTokenBuilder.AgentDwk
            || typ == AuthTokenBuilder.TokenType && dwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk)))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected JWT dwk.");
        var jwksUrl = await DiscoverAsync(issuer, dwk, ct).ConfigureAwait(false);
        var issuerKey = await ResolveDirectAsync(jwksUrl, kid, ct, issuer).ConfigureAwait(false);
        TokenVerifier.VerifiedToken verified;
        try
        {
            verified = await VerifyAsync(issuerKey).ConfigureAwait(false);
        }
        catch (TokenVerificationException)
        {
            var refreshed = await _jwksClient!.ForceRefreshKeyAsync(new Uri(jwksUrl), kid, issuer, ct).ConfigureAwait(false);
            if (refreshed is null) throw new AAuthVerificationException(SignatureErrorCode.UnknownKey, "Issuer key no longer exists.");
            if (refreshed.ComputeJwkThumbprint() == issuerKey.ComputeJwkThumbprint()) throw;
            issuerKey = refreshed;
            verified = await VerifyAsync(issuerKey).ConfigureAwait(false);
        }
        var key = info.Scheme == "self-jwt" ? issuerKey : SignatureKeyParser.Confirmation(verified.Payload);
        return new() { PublicKey = key, Info = WithKey(info, key), VerifiedToken = verified, IssuerKey = issuerKey,
            VerifiedIdentifier = verified.Issuer, KeyId = info.Scheme == "self-jwt" ? kid : key.ComputeJwkThumbprint() };

        Task<TokenVerifier.VerifiedToken> VerifyAsync(IAAuthKey signingKey) => companion is not null
            ? companion.VerifyAsync(info.Jwt!, signingKey, _tokenVerifier, ct)
            : Task.FromResult(_tokenVerifier.Verify(info.Jwt!, signingKey, typ!, dwk));
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

    private static SignatureKeyParser.ParsedSignatureKeyInfo WithKey(SignatureKeyParser.ParsedSignatureKeyInfo info, IAAuthKey key, string? jkt = null) => new()
    {
        Scheme = info.Scheme, Label = info.Label, ConfirmationKey = key, Jkt = jkt ?? key.ComputeJwkThumbprint(),
        Jwt = info.Jwt, Header = info.Header, Payload = info.Payload, Identifier = info.Identifier,
        Dwk = info.Dwk, Kid = info.Kid, JwksUri = info.JwksUri,
    };

    private async Task<IAAuthKey> ResolveJwksUriAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        var url = await DiscoverAsync(info.Identifier!, info.Dwk!, ct).ConfigureAwait(false);
        return await ResolveDirectAsync(url, info.Kid!, ct, info.Identifier!).ConfigureAwait(false);
    }

    private async Task<string> DiscoverAsync(string identifier, string dwk, CancellationToken ct)
    {
        if (_metadataClient is null) throw new InvalidOperationException("MetadataClient is required for issuer discovery.");
        if (!_metadataClient.Policy.IsValidIdentifier(identifier) || string.IsNullOrEmpty(dwk) || dwk is "." or ".."
            || dwk.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_')))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Invalid identifier or metadata name.");
        var metadata = await _metadataClient.FetchAsync(_metadataClient.GetUrl(identifier, dwk), ct).ConfigureAwait(false);
        var issuer = SignatureKeyParser.Text(metadata, "issuer");
        if (issuer is null) throw new AAuthVerificationException(SignatureErrorCode.IssuerMissing, "Metadata issuer is missing.");
        if (issuer != identifier) throw new AAuthVerificationException(SignatureErrorCode.IssuerMismatch, "Metadata issuer does not match identifier.");
        return SignatureKeyParser.Text(metadata, "jwks_uri")
            ?? throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Metadata jwks_uri is missing.");
    }

    private async Task<IAAuthKey> ResolveDirectAsync(string url, string kid, CancellationToken ct, string? issuer = null)
    {
        if (_jwksClient is null) throw new InvalidOperationException("JwksClient is required for key discovery.");
        var uri = _jwksClient.Policy.ValidateUrl(url);
        var key = issuer is null
            ? await _jwksClient.ResolveKeyAsync(uri, kid, ct).ConfigureAwait(false)
            : await _jwksClient.ResolveKeyAsync(uri, kid, issuer, ct).ConfigureAwait(false);
        return key ?? throw new AAuthVerificationException(SignatureErrorCode.UnknownKey, "Selected key not found.");
    }

}
