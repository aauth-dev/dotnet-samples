using System;
using System.Collections.Generic;

namespace AAuth.Server.Verification;

/// <summary>
/// Configuration for <see cref="AAuthVerificationMiddleware"/> which
/// performs both HTTP signature PoP verification AND JWT issuer signature
/// verification in a single pass.
/// </summary>
public sealed class AAuthVerificationOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    public IReadOnlyList<string> AcceptedSchemes { get; init; } = ["jwt"];
    public string SignatureLabel { get; init; } = "sig";
    public IReadOnlyCollection<string> RequiredComponents { get; init; } = [];
    public bool GenericSignatureKeys { get; init; }
    /// <summary>
    /// Optional allow-list of trusted Agent Provider issuers (for <c>aa-agent+jwt</c>).
    /// When <c>null</c>, any issuer whose JWKS is resolvable is accepted; an empty
    /// set denies all. Composed by AND with <see cref="IsTrustedAgentProviderIssuer"/>.
    /// </summary>
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; init; }

    /// <summary>
    /// Optional trust policy for Agent Provider issuers, evaluated per <c>iss</c>
    /// during agent-token verification and composed by AND with
    /// <see cref="TrustedAgentProviderIssuers"/>. <c>null</c> ⇒ no policy constraint.
    /// </summary>
    public Func<string, bool>? IsTrustedAgentProviderIssuer { get; init; }

    /// <summary>
    /// Optional allow-list of trusted Person Server / Access Server issuers (for
    /// <c>aa-auth+jwt</c>).
    /// <para>
    /// <b>Open by default (spec-compliant):</b> when <c>null</c>, any auth token
    /// from a <em>verifiable</em> issuer is accepted — PS-asserted access accepts
    /// identity claims from any Person Server, namespaced by <c>iss</c> (§Trust
    /// Posture in PS-Asserted Access). An <b>empty</b> set denies all (a deliberate
    /// kill-switch). A non-empty set restricts to the listed issuers. Composed by
    /// AND with <see cref="IsTrustedAuthTokenIssuer"/>. Signature-only flows
    /// (<c>hwk</c>/<c>jkt-jwt</c>/<c>jwks_uri</c>) carry no auth-token issuer and
    /// are unaffected.
    /// </para>
    /// </summary>
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; init; }

    /// <summary>
    /// Optional trust policy for auth-token issuers (Person Servers / Access
    /// Servers), evaluated per <c>iss</c> during auth-token verification and
    /// composed by AND with <see cref="TrustedAuthTokenIssuers"/>. <c>null</c> ⇒ no
    /// policy constraint. Assign <see cref="AAuthTrust.Any"/> to state intentional
    /// open trust explicitly (and suppress the startup warning).
    /// </summary>
    public Func<string, bool>? IsTrustedAuthTokenIssuer { get; init; }

    /// <summary>
    /// This resource's own identifier — used for <c>aud</c> validation on auth tokens.
    /// When null, audience is not validated by the middleware (caller must check).
    /// </summary>
    public string? ResourceIdentifier { get; init; }
    public Func<Microsoft.AspNetCore.Http.HttpContext, string?>? ExpectedAccount { get; init; }

    /// <summary>
    /// Enable implemented generic Signature Keys schemes. JWT assertions still
    /// require issuer verification. AAuth-only endpoints use the default jwt policy.
    /// </summary>
    /// <param name="clock">Optional clock for signature-freshness checks (testing).</param>
    /// <returns>A fresh generic-scheme policy.</returns>
    public static AAuthVerificationOptions Generic(Func<DateTimeOffset>? clock = null)
        => new()
        {
            AcceptedSchemes = ["jwt", "hwk", "jkt-jwt", "jwks_uri", "jwks", "self-jwt"],
            Clock = clock,
        };

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
