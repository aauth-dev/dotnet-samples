using System.Collections.Concurrent;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Stores exact proposal bytes keyed by their R3 hash.</summary>
public sealed class R3ProposalStore
{
    private readonly ConcurrentDictionary<string, byte[]> _bytesByHash = new(StringComparer.Ordinal);

    public StoredR3Proposal Add(R3ProposalDocument proposal, Uri baseUri, string pathPrefix = "/r3/proposals")
    {
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(baseUri);
        var bytes = proposal.ToUtf8Bytes();
        var s256 = R3Hash.ComputeS256(bytes);
        _bytesByHash[s256] = bytes;
        var uri = new Uri(baseUri, $"{pathPrefix.TrimEnd('/')}/{Uri.EscapeDataString(s256)}");
        return new StoredR3Proposal(uri.ToString(), s256, bytes);
    }

    public StoredR3Proposal AddBytes(byte[] bytes, Uri baseUri, string pathPrefix = "/r3/proposals")
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(baseUri);
        var copy = bytes.ToArray();
        var s256 = R3Hash.ComputeS256(copy);
        _bytesByHash[s256] = copy;
        var uri = new Uri(baseUri, $"{pathPrefix.TrimEnd('/')}/{Uri.EscapeDataString(s256)}");
        return new StoredR3Proposal(uri.ToString(), s256, copy);
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
