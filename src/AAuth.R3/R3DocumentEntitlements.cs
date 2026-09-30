using System.Collections.Concurrent;

namespace AAuth.R3;

/// <summary>
/// Which servers may read an R3 document (r3 #r3-document-access-restriction): the Access
/// Server in <c>aud</c> and the Person Server in <c>ps</c> of an unexpired resource token
/// that carries the exact <c>r3_uri</c>/<c>r3_s256</c> pair.
/// </summary>
public interface IR3DocumentEntitlements
{
    /// <summary>Allow <paramref name="reader"/> to read the document named by one resource token until its expiry.</summary>
    ValueTask EntitleAsync(string uri, string s256, string reader, string resourceTokenId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>Whether <paramref name="reader"/> may read the exact document URI and hash now.</summary>
    ValueTask<bool> IsEntitledAsync(string uri, string s256, string reader, CancellationToken cancellationToken = default);
}

/// <summary>In-memory <see cref="IR3DocumentEntitlements"/>; state is lost on restart and not shared across instances.</summary>
public sealed class InMemoryR3DocumentEntitlements(TimeProvider? timeProvider = null) : IR3DocumentEntitlements
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, Entitlement>> _readers = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public ValueTask EntitleAsync(string uri, string s256, string reader, string resourceTokenId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);
        ArgumentException.ThrowIfNullOrEmpty(s256);
        ArgumentException.ThrowIfNullOrEmpty(reader);
        ArgumentException.ThrowIfNullOrEmpty(resourceTokenId);
        _readers.GetOrAdd(Key(uri, s256), _ => new(StringComparer.Ordinal))[reader + "\n" + resourceTokenId] = new(expiresAt);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<bool> IsEntitledAsync(string uri, string s256, string reader, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        if (!_readers.TryGetValue(Key(uri, s256), out var readers)) return ValueTask.FromResult(false);
        foreach (var (key, entitlement) in readers)
        {
            if (entitlement.ExpiresAt <= now)
            {
                readers.TryRemove(key, out _);
                continue;
            }
            if (key.StartsWith(reader + "\n", StringComparison.Ordinal)) return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }

    private static string Key(string uri, string s256) => uri + "\n" + s256;
    private sealed record Entitlement(DateTimeOffset ExpiresAt);
}
