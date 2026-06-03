using System;
using System.Collections.Generic;

namespace AAuth.Server.Verification;

/// <summary>
/// Typed verification result exposed via <c>HttpContext.Features</c> after
/// AAuth verification middleware runs. Provides structured access to all
/// verified claims for use by authentication handlers and authorization policies.
/// </summary>
public sealed class AAuthVerificationResult
{
    /// <summary>Authorization level determined from token type.</summary>
    public required AAuthLevel Level { get; init; }

    /// <summary>The Signature-Key scheme (jwt, hwk, jwks_uri, jkt-jwt).</summary>
    public required string Scheme { get; init; }

    /// <summary>Token type from JWT <c>typ</c> header.</summary>
    public AAuthTokenType TokenType { get; init; }

    /// <summary>Issuer (<c>iss</c>) from the JWT, or null for non-JWT schemes.</summary>
    public string? Issuer { get; init; }

    /// <summary>Agent identifier (from <c>sub</c> on agent tokens, <c>agent</c> on auth tokens).</summary>
    public string? Agent { get; init; }

    /// <summary>Subject (<c>sub</c>) — pairwise identifier for the person (on auth tokens).</summary>
    public string? Subject { get; init; }

    /// <summary>Verified scopes from the token's <c>scope</c> claim (space-separated → set).</summary>
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>();

    /// <summary>Verified roles from the auth token's <c>roles</c> claim ([@!RFC9068]).</summary>
    public IReadOnlySet<string> Roles { get; init; } = new HashSet<string>();

    /// <summary>Verified groups from the auth token's <c>groups</c> claim ([@!RFC9068]).</summary>
    public IReadOnlySet<string> Groups { get; init; } = new HashSet<string>();

    /// <summary>Actor subject from <c>act.sub</c> (identifies the agent in auth tokens).</summary>
    public string? ActorSubject { get; init; }

    /// <summary>JWK thumbprint of the signing key (available for all schemes).</summary>
    public string? Jkt { get; init; }

    /// <summary>Whether the JWT issuer's signature was verified against JWKS.</summary>
    public bool IssuerVerified { get; init; }
}
