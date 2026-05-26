using System;
using System.Collections.Generic;

namespace AAuth.Server;

/// <summary>
/// Configuration for <see cref="AAuthVerificationMiddleware"/> which
/// performs both HTTP signature PoP verification AND JWT issuer signature
/// verification in a single pass.
/// </summary>
public sealed class AAuthVerificationOptions
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

    /// <summary>
    /// Maximum depth of nested <c>act</c> claims allowed in auth tokens.
    /// Prevents unbounded chain depth. Default: <c>10</c>.
    /// </summary>
    public int MaxActDepth { get; init; } = 10;

    /// <summary>
    /// Tolerance applied to <c>exp</c>/<c>iat</c> checks on tokens.
    /// Default: 30 seconds.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum allowed skew into the future for HTTP signature timestamps.
    /// Default: 5 seconds.
    /// </summary>
    public TimeSpan MaxFutureSkew { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Clock function for time-dependent checks (signature freshness, token expiry).
    /// Default: <c>null</c> (uses <see cref="DateTimeOffset.UtcNow"/>).
    /// Inject a fixed clock for deterministic testing.
    /// </summary>
    public Func<DateTimeOffset>? Clock { get; init; }
}
