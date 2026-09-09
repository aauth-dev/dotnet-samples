using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// Qualified token inventory and independent per-request replay state.
/// </summary>
public interface IJtiStore
{
    /// <summary>
    /// Record a verified request signature. Returns false for an exact replay.
    /// </summary>
    /// <param name="requestKey">The verified signature's replay key, not a token ID.</param>
    /// <param name="expiration">When the token expires (entries can be evicted after this).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> TryRecordRequestAsync(string requestKey, DateTimeOffset expiration, CancellationToken ct = default);

    /// <summary>Register a verified token. False when expired or already revoked.</summary>
    Task<bool> RegisterAsync(TokenKey token, DateTimeOffset expiration, CancellationToken ct = default);

    /// <summary>
    /// Revoke a known token. False means unknown; repeated known revocation succeeds.
    /// </summary>
    Task<bool> RevokeAsync(TokenKey token, CancellationToken ct = default);

    /// <summary>
    /// Check local token and ancestor revocation independently of request replay.
    /// </summary>
    Task<bool> IsRevokedAsync(TokenKey token, CancellationToken ct = default);

    /// <summary>Atomically attach a grant to known live sources, rejecting revoked local ancestry and dependency cycles.</summary>
    Task<bool> RegisterGrantAsync(IReadOnlyCollection<TokenKey> sources, TokenGrant grant, CancellationToken ct = default);

    /// <summary>Return unexpired grants issued or provided for the exact source token.</summary>
    Task<IReadOnlyList<TokenGrant>> GetGrantsAsync(TokenKey source, CancellationToken ct = default);
}
