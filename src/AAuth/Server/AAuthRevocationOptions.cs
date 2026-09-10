using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

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
    /// Explicitly permit an authenticated issuer to revoke its own token pairs.
    /// </summary>
    public bool AllowTokenIssuer { get; set; }

    /// <summary>
    /// Person Servers explicitly trusted to revoke provided tokens.
    /// </summary>
    public IReadOnlyCollection<string>? TrustedPersonServers { get; set; }

    /// <summary>
    /// Optional target-aware trust policy for authenticated Person Servers.
    /// </summary>
    public Func<string, TokenKey, bool>? IsTrustedPersonServer { get; set; }

    public Func<TokenGrant, CancellationToken, Task<bool>>? RevokeGrantAsync { get; set; }

    internal bool IsAuthorizedRevoker(string callerId, TokenKey token)
        => (AllowTokenIssuer && string.Equals(callerId, token.Issuer, StringComparison.Ordinal))
        || (TrustedPersonServers?.Contains(callerId, StringComparer.Ordinal) ?? false)
        || (IsTrustedPersonServer?.Invoke(callerId, token) ?? false);
}
