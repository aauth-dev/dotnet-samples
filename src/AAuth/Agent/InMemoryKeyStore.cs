using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Agent;

/// <summary>
/// In-memory <see cref="IKeyStore"/> for development and testing.
/// Keys are lost on process exit.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore
{
    private readonly ConcurrentDictionary<string, IAAuthKey> _keys = new();

    /// <inheritdoc/>
    public Task<IAAuthKey?> LoadAsync(string keyId, CancellationToken ct = default)
    {
        _keys.TryGetValue(keyId, out var key);
        return Task.FromResult(key);
    }

    /// <inheritdoc/>
    public Task StoreAsync(string keyId, IAAuthKey key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(key);
        _keys[keyId] = key;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task DeleteAsync(string keyId, CancellationToken ct = default)
    {
        _keys.TryRemove(keyId, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<string[]> ListAsync(CancellationToken ct = default)
    {
        return Task.FromResult(_keys.Keys.ToArray());
    }
}
