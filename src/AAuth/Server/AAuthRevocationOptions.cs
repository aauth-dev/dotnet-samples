using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Errors;

namespace AAuth.Server;

/// <summary>
/// Acceptance and cascade policy for the AAuth revocation endpoint
/// (<see cref="RevocationEndpoint.MapAAuthRevocationEndpoint(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder, IJtiStore, Action{AAuthRevocationOptions}?, string)"/>).
/// </summary>
/// <remarks>
/// Per §Token Revocation the issuer is not a request parameter: the recipient keys
/// the revocation by <c>(verified caller, jti)</c>, so a caller can only revoke its
/// own tokens. <see cref="IsAcceptedIssuer"/> decides which verified callers the
/// recipient accepts revocations from; others get <c>403 unsupported_iss</c>. The
/// generic endpoint is <b>deny-by-default</b>.
/// </remarks>
public sealed class AAuthRevocationOptions
{
    /// <summary>
    /// Verified server identities (<c>jwks_uri</c>, <c>jwks</c>, <c>self-jwt</c>) this
    /// recipient accepts revocations from. <see langword="null"/> accepts none; assign
    /// <see cref="AAuthTrust.Any"/> to accept any verified issuer.
    /// </summary>
    public Func<string, bool>? IsAcceptedIssuer { get; set; }

    /// <summary>
    /// Latest accepted <c>exp</c>, relative to now: a revocation naming a later
    /// expiration is <c>400 invalid_request</c>. Bounds how long an unseen revocation
    /// is held. Default 24 hours, the longest recommended agent token lifetime.
    /// </summary>
    public TimeSpan MaxTokenLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Per-issuer entry and rate bounds; beyond either the caller gets <c>429 rate_limited</c>.
    /// On by default; <see langword="null"/> disables them.
    /// </summary>
    public RevocationLimits? Limits { get; set; } = new();

    /// <summary>
    /// Report the cascade in the <c>200</c> body's <c>downstream</c> array (an AS to a PS).
    /// A PS sets this to <see langword="false"/>: it answers an agent provider with an empty body.
    /// </summary>
    public bool ReportDownstream { get; set; } = true;

    /// <summary>
    /// Revoke <see cref="TokenGrant.Token"/> at its recipient <see cref="TokenGrant.Resource"/>,
    /// returning <see langword="null"/> once recorded there. Unset means every downstream
    /// revocation is <see cref="RevocationDownstreamError.RevocationUnsupported"/>.
    /// </summary>
    public Func<TokenGrant, CancellationToken, Task<RevocationDownstreamError?>>? RevokeGrantAsync { get; set; }

    // Set by MapAAuthIssuerRevocation: the recipient's own identity, clock, and AS federation path.
    internal string? Issuer { get; set; }
    internal TimeProvider Clock { get; set; } = TimeProvider.System;
    internal Func<TokenGrant, CancellationToken, Task<RevocationDownstreamError?>>? RevokeAtAccessServerAsync { get; set; }
}
