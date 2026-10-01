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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
    private readonly IServiceProvider? _services;
    private readonly string? _expectedDwk;

    /// <summary>Create the resolver.</summary>
    /// <param name="jwksClient">Required for the <c>jwks_uri</c> scheme. The <c>jkt-jwt</c> scheme is self-anchored (draft-05 §3.4) and needs no external client.</param>
    public DefaultSignatureKeyResolver(JwksClient? jwksClient = null, MetadataClient? metadataClient = null,
        TokenVerifier? tokenVerifier = null, IEnumerable<ISignatureTokenVerifier>? tokenVerifiers = null,
        IServiceProvider? services = null, string? expectedDwk = null)
    {
        _jwksClient = jwksClient;
        _metadataClient = metadataClient;
        _tokenVerifier = tokenVerifier ?? new TokenVerifier { EgressPolicy = metadataClient?.Policy ?? AAuthEgressPolicy.Production };
        _tokenVerifiers = tokenVerifiers?.ToArray() ?? [];
        _services = services;
        _expectedDwk = expectedDwk;
    }

    internal DefaultSignatureKeyResolver WithValidation(JwksClient? jwks, MetadataClient? metadata, TokenVerifier verifier, string? expectedDwk) =>
        new(jwks ?? _jwksClient, metadata ?? _metadataClient, verifier, _tokenVerifiers, _services, expectedDwk);

    public async Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(info);

        if (info.Scheme is "jwt" or "self-jwt")
            return await ResolveAssertionAsync(info, ct).ConfigureAwait(false);
        if (info.Scheme == "jkt-jwt")
        {
            var naming = NamingTokenVerifier.Verify(info.Jwt!, _tokenVerifier.TimeProvider.GetUtcNow(), _tokenVerifier.ClockSkew);
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
        var builtin = info.Scheme == AAuthConstants.Schemes.Jwt
            && typ is AgentTokenBuilder.TokenType or AuthTokenBuilder.TokenType or PersonTokenBuilder.TokenType;
        if (!builtin && companion is null)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected JWT typ for this signing scheme.");
        var issuer = SignatureKeyParser.Text(info.Payload, "iss");
        var dwk = SignatureKeyParser.Text(info.Payload, "dwk");
        var kid = SignatureKeyParser.Text(info.Header, "kid");
        var expectedDwk = typ == AuthTokenBuilder.TokenType ? _expectedDwk : null;
        var requiresMetadata = builtin || info.Scheme == AAuthConstants.Schemes.SelfJwt || issuer is not null && dwk is not null;
        try
        {
            if (builtin) TokenVerifier.ValidateStructure(info.Header!, info.Payload!, typ, _tokenVerifier.EgressPolicy);
            else TokenVerifier.ValidateAssertionStructure(info.Header!, info.Payload!, typ, _tokenVerifier.EgressPolicy,
                requiresMetadata, requireConfirmationKey: info.Scheme != AAuthConstants.Schemes.SelfJwt);
        }
        catch (TokenVerificationException exception)
        {
            throw new AAuthVerificationException(exception.Code, exception.Message, exception);
        }
        NamingTokenVerifier.ValidateTime(info.Payload!, _tokenVerifier.TimeProvider.GetUtcNow(), expirationSkew: TimeSpan.Zero,
            requireIssuedAt: builtin, issuedAtWindow: _tokenVerifier.ClockSkew);
        if (builtin && (typ == AgentTokenBuilder.TokenType && dwk != AgentTokenBuilder.AgentDwk
            || typ == PersonTokenBuilder.TokenType && dwk != PersonTokenBuilder.PersonDwk
            || typ == AuthTokenBuilder.TokenType && dwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk)))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected JWT dwk.");

        IAAuthKey issuerKey;
        string? jwksUrl = null;
        if (requiresMetadata)
        {
            if (issuer is null) throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires iss.");
            if (dwk is null) throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires dwk.");
            if (expectedDwk is not null && dwk != expectedDwk)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected JWT dwk.");
            if (kid is null) throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires kid.");
            jwksUrl = await DiscoverAsync(issuer, dwk, ct).ConfigureAwait(false);
            issuerKey = await ResolveDirectAsync(jwksUrl, kid, ct, issuer).ConfigureAwait(false);
        }
        else
        {
            if (companion is null || info.Scheme != AAuthConstants.Schemes.Jwt)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires issuer metadata.");
            issuerKey = await companion.ResolveIssuerKeyAsync(CreateIssuerKeyContext(info, typ!, expectedDwk), ct).ConfigureAwait(false)
                ?? throw new AAuthVerificationException(issuer is not null || kid is not null
                    ? SignatureErrorCode.UnknownKey : SignatureErrorCode.InvalidJwt,
                    "Companion JWT issuer key was not resolved.");
        }

        TokenVerifier.VerifiedToken verified;
        try
        {
            verified = await VerifyAsync(issuerKey).ConfigureAwait(false);
        }
        catch (TokenVerificationException)
        {
            if (jwksUrl is null || kid is null || issuer is null || _jwksClient is null) throw;
            var refreshed = await _jwksClient!.ForceRefreshKeyAsync(new Uri(jwksUrl), kid, issuer, ct).ConfigureAwait(false);
            if (refreshed is null) throw new AAuthVerificationException(SignatureErrorCode.UnknownKey, "Issuer key no longer exists.");
            if (refreshed.ComputeJwkThumbprint() == issuerKey.ComputeJwkThumbprint()) throw;
            issuerKey = refreshed;
            verified = await VerifyAsync(issuerKey).ConfigureAwait(false);
        }
        var key = info.Scheme == "self-jwt" ? issuerKey : SignatureKeyParser.Confirmation(verified.Payload);
        WarnOnLongAgentToken(typ, verified);
        return new() { PublicKey = key, Info = WithKey(info, key), VerifiedToken = verified, IssuerKey = issuerKey,
            VerifiedIdentifier = verified.Issuer, KeyId = info.Scheme == "self-jwt" ? kid : key.ComputeJwkThumbprint() };

        Task<TokenVerifier.VerifiedToken> VerifyAsync(IAAuthKey signingKey)
        {
            if (companion is not null)
            {
                NamingTokenVerifier.VerifySignature(info.Jwt!, info.Header!, signingKey);
                return companion.VerifyAsync(CreateVerificationContext(info, typ!, signingKey, expectedDwk), ct);
            }
            return Task.FromResult(_tokenVerifier.Verify(info.Jwt!, signingKey, typ!, dwk!));
        }
    }

    private void WarnOnLongAgentToken(string? typ, TokenVerifier.VerifiedToken verified)
    {
        if (typ != AgentTokenBuilder.TokenType
            || verified.Payload["iat"] is not JsonValue iatNode
            || !iatNode.TryGetValue<long>(out var iat)
            || verified.Payload["exp"] is not JsonValue expNode
            || !expNode.TryGetValue<long>(out var exp)
            || exp - iat <= (long)AgentTokenBuilder.MaximumLifetime.TotalSeconds)
        {
            return;
        }

        _services?.GetService<ILoggerFactory>()
            ?.CreateLogger("AAuth.Verification")
            .LogWarning("Consumed agent token lifetime exceeds the recommended 24 hour maximum.");
    }

    private SignatureTokenIssuerKeyContext CreateIssuerKeyContext(SignatureKeyParser.ParsedSignatureKeyInfo info, string typ, string? expectedDwk) => new(
        info.Jwt!, info.Header!, info.Payload!, info.Scheme, typ, _tokenVerifier)
    {
        Issuer = SignatureKeyParser.Text(info.Payload, "iss"),
        Dwk = SignatureKeyParser.Text(info.Payload, "dwk"),
        Kid = SignatureKeyParser.Text(info.Header, "kid"),
        ExpectedDwk = expectedDwk,
        Services = _services,
    };

    private SignatureTokenVerificationContext CreateVerificationContext(SignatureKeyParser.ParsedSignatureKeyInfo info,
        string typ, IAAuthKey issuerKey, string? expectedDwk) => new(info.Jwt!, info.Header!, info.Payload!, info.Scheme, typ, issuerKey, _tokenVerifier)
    {
        Issuer = SignatureKeyParser.Text(info.Payload, "iss"),
        Dwk = SignatureKeyParser.Text(info.Payload, "dwk"),
        Kid = SignatureKeyParser.Text(info.Header, "kid"),
        ExpectedDwk = expectedDwk,
        Services = _services,
    };

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
