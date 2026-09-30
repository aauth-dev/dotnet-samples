using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// What a cached carrier token (person token or auth token) was obtained for. A token is reused
/// only for a request with the same key (#call-chaining, #missions, #account).
/// </summary>
/// <param name="AgentToken">The agent token the exchange was signed with.</param>
/// <param name="Upstream">The upstream token chained, if any.</param>
/// <param name="MissionS256">The mission, if any.</param>
/// <param name="Audience">The resource the carrier is for.</param>
/// <param name="Account">The account the request named, if any.</param>
/// <param name="KeyThumbprint">The JWK thumbprint of the key the carrier is bound to.</param>
public sealed record AAuthTokenCacheKey(string AgentToken, string? Upstream, string? MissionS256, string Audience,
    string? Account, string KeyThumbprint);

/// <summary>
/// Carrier tokens an agent obtained by exchange, reused across requests and, when shared,
/// across clients. Implementations are thread-safe and ignore expired entries.
/// </summary>
public interface IAAuthTokenCache
{
    /// <summary>The unexpired token cached for <paramref name="key"/>, if any.</summary>
    string? Get(AAuthTokenCacheKey key);

    /// <summary>Cache <paramref name="token"/> for <paramref name="key"/> until <paramref name="expiresAt"/>.</summary>
    void Set(AAuthTokenCacheKey key, string token, DateTimeOffset expiresAt);

    /// <summary>
    /// Return a cached token for <paramref name="key"/> other than <paramref name="presented"/> (the one a
    /// resource just refused), else run <paramref name="acquire"/> and cache its result. Concurrent callers
    /// for one key share a single acquisition.
    /// </summary>
    Task<string> AcquireAsync(AAuthTokenCacheKey key, string? presented, Func<CancellationToken, Task<string>> acquire,
        CancellationToken cancellationToken);

    /// <summary>
    /// Forget every cached token, for example when the person signs out. In-flight acquisitions
    /// still complete for their callers.
    /// </summary>
    void Clear();
}

/// <summary>The in-memory <see cref="IAAuthTokenCache"/>: per agent by default, shareable across clients.</summary>
public sealed class InMemoryAAuthTokenCache : IAAuthTokenCache
{
    private readonly object _gate = new();
    private readonly Dictionary<AAuthTokenCacheKey, (string Token, DateTimeOffset ExpiresAt)> _entries = new();
    private readonly Dictionary<AAuthTokenCacheKey, Task<string>> _inFlight = new();
    private readonly TimeProvider _clock;

    public InMemoryAAuthTokenCache(TimeProvider? timeProvider = null) => _clock = timeProvider ?? TimeProvider.System;

    public string? Get(AAuthTokenCacheKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock (_gate) return Fresh(key);
    }

    public void Set(AAuthTokenCacheKey key, string token, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(token);
        lock (_gate)
        {
            _entries[key] = (token, expiresAt);
            if (_entries.Count > 1024) Prune();
        }
    }

    public void Clear()
    {
        lock (_gate) _entries.Clear();
    }

    public async Task<string> AcquireAsync(AAuthTokenCacheKey key, string? presented,
        Func<CancellationToken, Task<string>> acquire, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(acquire);
        Task<string> acquisition;
        lock (_gate)
        {
            if (Fresh(key) is { } cached && cached != presented) return cached;
            if (!_inFlight.TryGetValue(key, out acquisition!))
                _inFlight[key] = acquisition = RunAsync(key, acquire, cancellationToken);
        }
        return await acquisition.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> RunAsync(AAuthTokenCacheKey key, Func<CancellationToken, Task<string>> acquire,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        try
        {
            var token = await acquire(cancellationToken).ConfigureAwait(false);
            Set(key, token, AAuthTokenHolder.ExpiresAt(token));
            return token;
        }
        finally
        {
            lock (_gate) _inFlight.Remove(key);
        }
    }

    private string? Fresh(AAuthTokenCacheKey key)
        => _entries.TryGetValue(key, out var entry) && entry.ExpiresAt > _clock.GetUtcNow() ? entry.Token : null;

    private void Prune()
    {
        var now = _clock.GetUtcNow();
        foreach (var expired in new List<AAuthTokenCacheKey>(_entries.Keys))
            if (_entries[expired].ExpiresAt <= now) _entries.Remove(expired);
    }
}
