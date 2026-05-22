using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// In-memory <see cref="IJtiStore"/> for development and testing.
/// NOT production-grade — state is lost on restart, no distributed support.
/// </summary>
public sealed class InMemoryJtiStore : IJtiStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();
    private readonly ConcurrentDictionary<string, bool> _revoked = new();

    /// <inheritdoc/>
    public Task<bool> TryRecordAsync(string jti, DateTimeOffset expiration, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        // If already revoked, reject immediately.
        if (_revoked.ContainsKey(jti))
            return Task.FromResult(false);
        var added = _seen.TryAdd(jti, expiration);
        return Task.FromResult(added);
    }

    /// <inheritdoc/>
    public Task RevokeAsync(string jti, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        _revoked[jti] = true;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        return Task.FromResult(_revoked.ContainsKey(jti));
    }

    /// <summary>
    /// Evict expired entries (call periodically if memory matters).
    /// </summary>
    public void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _seen)
        {
            if (kv.Value < now)
            {
                _seen.TryRemove(kv.Key, out _);
            }
        }
    }
}
