using System.Collections.Concurrent;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Retains exact document and proposal bytes for the process lifetime.
/// Capacity exhaustion rejects new content instead of evicting published references.</summary>
public sealed class R3ProposalStore
{
    private readonly ConcurrentDictionary<string, byte[]> _bytesByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, bool>> _readers = new(StringComparer.Ordinal);
    private readonly int _maxEntries;

    /// <summary>
    /// Entitle <paramref name="personServer"/> to read the content <paramref name="s256"/>:
    /// the PS a resource token referencing it names in <c>ps</c>.
    /// </summary>
    public void Entitle(string s256, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _readers.GetOrAdd(s256, _ => new(StringComparer.Ordinal))[personServer] = true;
    }

    /// <summary>Whether <paramref name="personServer"/> was entitled to read <paramref name="s256"/>.</summary>
    public bool IsEntitled(string s256, string personServer)
        => _readers.TryGetValue(s256, out var readers) && readers.ContainsKey(personServer);

    public R3ProposalStore(int maxEntries = 1024)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntries);
        _maxEntries = maxEntries;
    }

    public StoredR3Proposal Add(R3ProposalDocument proposal, Uri baseUri, string pathPrefix = "/r3/proposals", R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(baseUri);
        return Store(proposal.ToUtf8Bytes(schemas: schemas), baseUri, pathPrefix);
    }

    public StoredR3Proposal AddBytes(byte[] bytes, Uri baseUri, string pathPrefix = "/r3/proposals")
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(baseUri);
        return Store(bytes.ToArray(), baseUri, pathPrefix);
    }

    private StoredR3Proposal Store(byte[] bytes, Uri baseUri, string pathPrefix)
    {
        var s256 = R3Hash.ComputeS256(bytes);
        var uri = new Uri(baseUri, $"{pathPrefix.TrimEnd('/')}/{Uri.EscapeDataString(s256)}");
        lock (_bytesByHash)
        {
            if (!_bytesByHash.ContainsKey(s256))
            {
                if (_bytesByHash.Count >= _maxEntries)
                    throw new InvalidOperationException("R3 content store capacity exhausted; published references cannot be evicted.");
                _bytesByHash[s256] = bytes;
            }
        }
        return new StoredR3Proposal(uri.ToString(), s256, bytes.ToArray());
    }

    public bool TryGet(string s256, out byte[] bytes)
    {
        if (_bytesByHash.TryGetValue(s256, out var stored))
        {
            bytes = stored.ToArray();
            return true;
        }
        bytes = [];
        return false;
    }
}

public sealed record StoredR3Proposal(string Uri, string S256, byte[] Bytes);
