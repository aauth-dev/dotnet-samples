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
    public IReadOnlyList<string> AcceptedSchemes { get; set; } = ["jwt"];
    public string SignatureLabel { get; set; } = "sig";
    public IReadOnlyCollection<string> RequiredComponents { get; set; } = [];

    /// <summary>
    /// When <see langword="true"/>, a request that carries a body MUST also cover
    /// <c>content-type</c> and <c>content-digest</c> (§Covered Components: required
    /// on every body-bearing request to a PS or AS endpoint). A request without a
    /// body is unaffected. A request that omits them fails with <c>invalid_input</c>
    /// naming them in <c>required_input</c>, before any handler runs.
    /// </summary>
    public bool RequireBodyCoverage { get; set; }
    public bool GenericSignatureKeys { get; set; }

    /// <summary>
    /// Trust for agent-token, auth-token and person-token issuers. Open by default
    /// (spec-compliant): any <em>verifiable</em> issuer is accepted, namespaced by
    /// <c>iss</c> (§Trust Posture in PS-Asserted Access). Signature-only schemes
    /// (<c>hwk</c>/<c>jkt-jwt</c>/<c>jwks_uri</c>) carry no issuer and are unaffected.
    /// </summary>
    public AAuthTrustOptions Trust { get; set; } = new();

    /// <summary>
    /// This resource's own identifier — used for <c>aud</c> validation on auth tokens.
    /// When null, audience is not validated by the middleware (caller must check).
    /// </summary>
    public string? ResourceIdentifier { get; set; }
    public Func<Microsoft.AspNetCore.Http.HttpContext, string?>? ExpectedAccount { get; set; }

    /// <summary>
    /// Enable implemented generic Signature Keys schemes. JWT assertions still
    /// require issuer verification. AAuth-only endpoints use the default jwt policy.
    /// </summary>
    /// <param name="timeProvider">Optional time source for signature-freshness checks (testing).</param>
    /// <returns>A fresh generic-scheme policy.</returns>
    public static AAuthVerificationOptions Generic(TimeProvider? timeProvider = null)
        => new()
        {
            AcceptedSchemes = ["jwt", "hwk", "jkt-jwt", "jwks_uri", "jwks", "self-jwt"],
            TimeProvider = timeProvider ?? TimeProvider.System,
        };

    /// <summary>
    /// Tolerance applied to <c>exp</c>/<c>iat</c> checks on tokens.
    /// Default: 30 seconds.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Time source for signature freshness and token expiry.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}
