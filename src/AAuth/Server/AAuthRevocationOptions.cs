using System;
using System.Collections.Generic;
using System.Linq;

namespace AAuth.Server;

/// <summary>
/// Authorization policy for the AAuth revocation endpoint
/// (<see cref="RevocationEndpoint.MapAAuthRevocationEndpoint(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder, IJtiStore, Action{AAuthRevocationOptions}?, string)"/>).
/// </summary>
/// <remarks>
/// Per the AAuth spec (§Token Revocation, L2302) a resource that accepts revocation
/// MUST verify the caller's identity via HTTP Message Signatures and MUST only accept
/// revocation from the issuer of the token being revoked or from a trusted Person
/// Server. Revocation is therefore <b>deny-by-default</b> — the opposite of the
/// PS-asserted trust-lists, which are open by default — because the spec mandates the
/// restriction. The operator lists the caller identities (trusted PSes and/or the
/// token issuer's own identity) permitted to revoke; an unlisted caller is rejected.
/// </remarks>
public sealed class AAuthRevocationOptions
{
    /// <summary>
    /// Allow-list of caller identities (verified issuer URL or agent identifier)
    /// permitted to revoke. OR-composed with <see cref="IsTrustedRevoker"/>.
    /// </summary>
    public IReadOnlyCollection<string>? TrustedRevokers { get; set; }

    /// <summary>
    /// Optional predicate authorizing a verified caller identity, OR-composed with
    /// <see cref="TrustedRevokers"/>. <c>null</c> ⇒ no predicate.
    /// </summary>
    public Func<string, bool>? IsTrustedRevoker { get; set; }

    /// <summary>
    /// Deny-by-default authorization: a caller is allowed only when it is in
    /// <see cref="TrustedRevokers"/> or accepted by <see cref="IsTrustedRevoker"/>.
    /// </summary>
    internal bool IsAuthorizedRevoker(string callerId)
        => (TrustedRevokers is { } set && set.Contains(callerId))
        || (IsTrustedRevoker?.Invoke(callerId) ?? false);
}
