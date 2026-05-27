using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Crypto;

/// <summary>
/// In-memory <see cref="IKeyStore"/> for development and testing.
/// Keys are lost on process exit.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore
{
    private readonly ConcurrentDictionary<string, IAAuthKey> _keys = new();

    /// <inheritdoc/>
    public Task<IAAuthKey?> LoadAsync(string handle, CancellationToken ct = default)
    {
        _keys.TryGetValue(handle, out var key);
        return Task.FromResult(key);
    }

    /// <inheritdoc/>
    public Task StoreAsync(string handle, IAAuthKey key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(handle);
        ArgumentNullException.ThrowIfNull(key);
        _keys[handle] = key;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task DeleteAsync(string handle, CancellationToken ct = default)
    {
        _keys.TryRemove(handle, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<string[]> ListAsync(CancellationToken ct = default)
    {
        return Task.FromResult(_keys.Keys.ToArray());
    }
}
