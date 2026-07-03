using System.Collections.Concurrent;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Stores exact proposal bytes keyed by their R3 hash, with TTL eviction so a
/// client spamming per-call proposals can't grow the store without bound.</summary>
public sealed class R3ProposalStore
{
    // A proposal is fetched by the AS moments after issuance, so a generous TTL covers
    // the exchange while capping unbounded growth. Mirrors R3PendingStore.
    internal static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, (byte[] Bytes, DateTimeOffset CreatedAt)> _bytesByHash = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public R3ProposalStore(TimeProvider? timeProvider = null) => _timeProvider = timeProvider ?? TimeProvider.System;

    public StoredR3Proposal Add(R3ProposalDocument proposal, Uri baseUri, string pathPrefix = "/r3/proposals")
    {
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(baseUri);
        return Store(proposal.ToUtf8Bytes(), baseUri, pathPrefix);
    }

    public StoredR3Proposal AddBytes(byte[] bytes, Uri baseUri, string pathPrefix = "/r3/proposals")
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(baseUri);
        return Store(bytes.ToArray(), baseUri, pathPrefix);
    }

    private StoredR3Proposal Store(byte[] bytes, Uri baseUri, string pathPrefix)
    {
        Sweep();
        var s256 = R3Hash.ComputeS256(bytes);
        _bytesByHash[s256] = (bytes, _timeProvider.GetUtcNow());
        var uri = new Uri(baseUri, $"{pathPrefix.TrimEnd('/')}/{Uri.EscapeDataString(s256)}");
        return new StoredR3Proposal(uri.ToString(), s256, bytes);
    }

    public bool TryGet(string s256, out byte[] bytes)
    {
        Sweep();
        if (_bytesByHash.TryGetValue(s256, out var stored))
        {
            bytes = stored.Bytes.ToArray();
            return true;
        }
        bytes = [];
        return false;
    }

    // Drop proposals past the TTL so the store does not grow without bound.
    private void Sweep()
    {
        var cutoff = _timeProvider.GetUtcNow() - Ttl;
        foreach (var kv in _bytesByHash)
        {
            if (kv.Value.CreatedAt < cutoff)
            {
                _bytesByHash.TryRemove(kv.Key, out _);
            }
        }
    }
}

public sealed record StoredR3Proposal(string Uri, string S256, byte[] Bytes);
