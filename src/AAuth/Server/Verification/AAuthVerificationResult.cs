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
    public string? ReplayIdentity { get; init; }
    public DateTimeOffset? ReplayExpiresAt { get; init; }

    /// <summary>Authorization level determined from token type.</summary>
    public required AAuthLevel Level { get; init; }

    /// <summary>The Signature-Key scheme (jwt, hwk, jwks_uri, jkt-jwt).</summary>
    public required string Scheme { get; init; }

    /// <summary>Components the verified signature covers (without <c>key</c>/<c>tr</c>-parameterized entries).</summary>
    public IReadOnlySet<string> CoveredComponents { get; init; } = new HashSet<string>();

    /// <summary>Token type from JWT <c>typ</c> header.</summary>
    public AAuthTokenType TokenType { get; init; }

    /// <summary>Issuer (<c>iss</c>) from the JWT, or null for non-JWT schemes.</summary>
    public string? Issuer { get; init; }

    /// <summary>Agent identifier: the <c>sub</c> of an agent token. Person and auth tokens name no agent.</summary>
    public string? Agent { get; init; }

    /// <summary>Subject (<c>sub</c>): the agent for an agent token, the person's directed identifier for a person or auth token.</summary>
    public string? Subject { get; init; }
    public string? Account { get; init; }
    public bool AccountVerified { get; init; }

    /// <summary>The person's PS: a person token's <c>iss</c>, an auth token's <c>ps</c>.</summary>
    public string? PersonServer { get; init; }

    /// <summary>The mission the person or auth token is under (<c>mission_s256</c>).</summary>
    public string? MissionS256 { get; init; }

    /// <summary>Organization context (<c>tenant</c>); not part of the person identifier.</summary>
    public string? Tenant { get; init; }

    /// <summary>Verified scopes from the token's <c>scope</c> claim (space-separated → set).</summary>
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>();

    /// <summary>Verified roles from the auth token's <c>roles</c> claim ([@!RFC9068]).</summary>
    public IReadOnlySet<string> Roles { get; init; } = new HashSet<string>();

    /// <summary>Verified groups from the auth token's <c>groups</c> claim ([@!RFC9068]).</summary>
    public IReadOnlySet<string> Groups { get; init; } = new HashSet<string>();

    /// <summary>JWK thumbprint of the signing key (available for all schemes).</summary>
    public string? Jkt { get; init; }

    /// <summary>Whether the JWT issuer's signature was verified against JWKS.</summary>
    public bool IssuerVerified { get; init; }
}
