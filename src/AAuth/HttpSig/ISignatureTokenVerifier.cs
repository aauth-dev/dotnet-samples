using AAuth.Crypto;
using AAuth.Tokens;
using System.Text.Json.Nodes;

namespace AAuth.HttpSig;

/// <summary>Context for resolving an application-specific issuer key for a companion JWT.</summary>
public sealed record SignatureTokenIssuerKeyContext(
    string Jwt,
    JsonObject Header,
    JsonObject Payload,
    string Scheme,
    string TokenType,
    TokenVerifier TokenVerifier)
{
    /// <summary>The issuer claim when present; absent companion JWTs use application-specific key resolution.</summary>
    public string? Issuer { get; init; }

    /// <summary>The discovery well-known key claim when present.</summary>
    public string? Dwk { get; init; }

    /// <summary>The JOSE key id when present.</summary>
    public string? Kid { get; init; }

    /// <summary>
    /// Optional role-specific <c>dwk</c> pin. Verifiers that resolve application-specific keys
    /// MUST enforce this when the JWT carries a <c>dwk</c> claim.
    /// </summary>
    public string? ExpectedDwk { get; init; }

    /// <summary>The request service provider for application policy and stores, when available.</summary>
    public IServiceProvider? Services { get; init; }
}

/// <summary>Context for validating application-specific claims after the issuer key is known.</summary>
public sealed record SignatureTokenVerificationContext(
    string Jwt,
    JsonObject Header,
    JsonObject Payload,
    string Scheme,
    string TokenType,
    IAAuthKey IssuerKey,
    TokenVerifier TokenVerifier)
{
    /// <summary>The issuer claim when present.</summary>
    public string? Issuer { get; init; }

    /// <summary>The discovery well-known key claim when present.</summary>
    public string? Dwk { get; init; }

    /// <summary>The JOSE key id when present.</summary>
    public string? Kid { get; init; }

    /// <summary>Optional role-specific <c>dwk</c> pin supplied by the SDK role verifier.</summary>
    public string? ExpectedDwk { get; init; }

    /// <summary>The request service provider for application policy and stores, when available.</summary>
    public IServiceProvider? Services { get; init; }
}

public interface ISignatureTokenVerifier
{
    string Scheme { get; }
    string TokenType { get; }

    /// <summary>
    /// Resolve an issuer key for a companion <c>jwt</c> assertion whose <c>iss</c> or
    /// <c>dwk</c> claim is absent. Return <see langword="null"/> when no key is known.
    /// </summary>
    ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(
        SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken);

    /// <summary>Validate application-specific claims after the SDK verifies structure, time and signature.</summary>
    Task<TokenVerifier.VerifiedToken> VerifyAsync(
        SignatureTokenVerificationContext context, CancellationToken cancellationToken);
}
