using System;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// Abstraction for JTI (JWT Token Identifier) tracking: replay detection
/// and token revocation. Consumers swap in Redis/SQL implementations.
/// </summary>
public interface IJtiStore
{
    /// <summary>
    /// Record a JTI as seen. Returns <c>false</c> if the JTI was already
    /// recorded (replay detected).
    /// </summary>
    /// <param name="jti">The token's unique identifier.</param>
    /// <param name="expiration">When the token expires (entries can be evicted after this).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> TryRecordAsync(string jti, DateTimeOffset expiration, CancellationToken ct = default);

    /// <summary>
    /// Explicitly revoke a JTI before its natural expiration.
    /// </summary>
    Task RevokeAsync(string jti, CancellationToken ct = default);

    /// <summary>
    /// Check if a JTI has been revoked (not just seen — explicitly revoked).
    /// </summary>
    Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);
}
