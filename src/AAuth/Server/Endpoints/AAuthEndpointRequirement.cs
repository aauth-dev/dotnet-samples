using System;
using System.Collections.Generic;
using AAuth.Crypto;
using AAuth.Server.Verification;

namespace AAuth.Server.Endpoints;

/// <summary>
/// Per-endpoint AAuth requirement attached as routing metadata by
/// <c>RequireAAuth</c> / <c>RequireAAuthSignature</c> and read by the
/// <c>UseAAuth</c> middleware to verify (and, for auth-token mode, challenge)
/// the matched endpoint.
/// </summary>
public sealed class AAuthEndpointRequirement
{
    /// <summary>Verification/challenge mode for this endpoint.</summary>
    public AAuthAccessMode Mode { get; init; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>Required scope (the challenge requests it; authorization enforces it).</summary>
    public string? Scope { get; init; }

    /// <summary>Required role, enforced from the auth token's <c>roles</c> claim.</summary>
    public string? Role { get; init; }

    /// <summary>Copy a signed <c>AAuth-Mission</c> header into the issued resource token.</summary>
    public bool MissionAware { get; init; }
}

/// <summary>
/// Resource-level verification/challenge defaults for <c>UseAAuth</c>. The signing
/// key, key id, and resource identifier default from the DI-registered
/// <see cref="AAuth.Server.Metadata.AAuthResourceMetadataOptions"/> (so the only
/// per-call config a typical resource supplies is <em>trust</em>); the override
/// properties exist for the rare resource that needs them.
/// </summary>
public sealed class AAuthServerOptions
{
    /// <summary>Verify the auth-token issuer's JWKS signature. Default true.</summary>
    public bool RequireIssuerVerification { get; set; } = true;

    /// <summary>Allow-list of trusted PS/AS auth-token issuers. Null ⇒ accept any verifiable issuer; empty ⇒ deny all.</summary>
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; set; }

    /// <summary>Trust policy for PS/AS auth-token issuers, AND-composed with the allow-list.</summary>
    public Func<string, bool>? IsTrustedAuthTokenIssuer { get; set; }

    /// <summary>Allow-list of trusted Agent Provider issuers (for <c>aa-agent+jwt</c>).</summary>
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; set; }

    /// <summary>Trust policy for Agent Provider issuers, AND-composed with the allow-list.</summary>
    public Func<string, bool>? IsTrustedAgentProviderIssuer { get; set; }

    /// <summary>
    /// Explicit resource-token audience for the challenge. Set to an Access Server
    /// URL for four-party (federated) resources; when null the audience is the
    /// agent token's <c>ps</c> claim (three-party).
    /// </summary>
    public string? PersonServerAudience { get; set; }

    /// <summary>Override the resource identifier (default: DI metadata issuer).</summary>
    public string? ResourceIdentifier { get; set; }

    /// <summary>Override the challenge signing key (default: DI metadata first key).</summary>
    public AAuthKey? ResourceSigningKey { get; set; }

    /// <summary>Override the challenge key id (default: DI metadata first kid).</summary>
    public string? ResourceKeyId { get; set; }
}
