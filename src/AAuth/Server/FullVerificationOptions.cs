using System;
using System.Collections.Generic;

namespace AAuth.Server;

/// <summary>
/// Configuration for <see cref="AAuthFullVerificationMiddleware"/> which
/// performs both HTTP signature PoP verification AND JWT issuer signature
/// verification in a single pass.
/// </summary>
public sealed class FullVerificationOptions
{
    /// <summary>
    /// Optional allow-list of trusted Agent Provider issuers (for <c>aa-agent+jwt</c>).
    /// When null, any issuer whose JWKS is resolvable is accepted.
    /// </summary>
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; init; }

    /// <summary>
    /// Optional allow-list of trusted Person Server / Access Server issuers (for <c>aa-auth+jwt</c>).
    /// When null, any issuer whose JWKS is resolvable is accepted.
    /// </summary>
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; init; }

    /// <summary>
    /// This resource's own identifier — used for <c>aud</c> validation on auth tokens.
    /// When null, audience is not validated by the middleware (caller must check).
    /// </summary>
    public string? ResourceIdentifier { get; init; }

    /// <summary>
    /// When true, the middleware verifies the JWT issuer's signature via JWKS discovery.
    /// Default: <c>true</c>.
    /// </summary>
    public bool RequireIssuerVerification { get; init; } = true;
}
