using System.Collections;
using System.Diagnostics.CodeAnalysis;

namespace AAuth.Crypto;

/// <summary>
/// The signing keys of an issuer: every key it publishes in its JWKS, keyed by
/// <c>kid</c>, plus the active key it signs new tokens with. Rotation is
/// live: <see cref="Add"/> a new key (published but not yet used), then
/// <see cref="Activate"/> it, then <see cref="Remove"/> the old one once
/// tokens signed with it have expired. Readers always see a consistent
/// snapshot, so a running server picks up changes without a restart.
/// </summary>
/// <remarks>
/// Until <see cref="Activate"/> is called (or an active <c>kid</c> is passed
/// to the constructor), the first key added is active.
/// </remarks>
public sealed class AAuthSigningKeySet : IReadOnlyCollection<KeyValuePair<string, IAAuthSigner>>
{
    private readonly Lock _gate = new();
    private volatile Snapshot _snapshot;

    /// <summary>Create an empty set. <paramref name="active"/> names the active <c>kid</c>; it must be added before first use.</summary>
    public AAuthSigningKeySet(string? active = null)
    {
        if (active is not null) ArgumentException.ThrowIfNullOrEmpty(active);
        _snapshot = new Snapshot([], active);
    }

    /// <summary>Create a set holding one key, which is active.</summary>
    public AAuthSigningKeySet(string keyId, IAAuthSigner signer) : this(keyId) => Add(keyId, signer);

    /// <summary>The number of published keys.</summary>
    public int Count => _snapshot.Entries.Length;

    /// <summary>The published key ids, in insertion order.</summary>
    public IReadOnlyList<string> KeyIds => Array.ConvertAll(_snapshot.Entries, entry => entry.Key);

    /// <summary>The active key id and signer, read atomically.</summary>
    /// <exception cref="InvalidOperationException">The set is empty, or the named active key was never added.</exception>
    public (string KeyId, IAAuthSigner Signer) Active => _snapshot.ResolveActive();

    /// <summary>The active key id. Prefer <see cref="Active"/> when you also need the signer.</summary>
    public string ActiveKeyId => Active.KeyId;

    /// <summary>Get or replace the signer for <paramref name="keyId"/>. Setting adds the key when absent.</summary>
    public IAAuthSigner this[string keyId]
    {
        get => TryGetSigner(keyId, out var signer)
            ? signer
            : throw new KeyNotFoundException($"No signing key with kid '{keyId}'.");
        set => Upsert(keyId, value, replace: true);
    }

    /// <summary>Publish a new key. Throws when <paramref name="keyId"/> is already present.</summary>
    public AAuthSigningKeySet Add(string keyId, IAAuthSigner signer)
    {
        Upsert(keyId, signer, replace: false);
        return this;
    }

    /// <summary>Make <paramref name="keyId"/> the key new tokens are signed with.</summary>
    public AAuthSigningKeySet Activate(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            var current = _snapshot;
            if (current.IndexOf(keyId) < 0)
                throw new InvalidOperationException($"Cannot activate unknown signing key '{keyId}'.");
            _snapshot = current with { ActiveKeyId = keyId };
        }
        return this;
    }

    /// <summary>Stop publishing <paramref name="keyId"/>. The active key cannot be removed.</summary>
    public bool Remove(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            var current = _snapshot;
            var index = current.IndexOf(keyId);
            if (index < 0) return false;
            if (current.Entries.Length > 0 && current.ResolveActiveOrDefault()?.KeyId == keyId)
                throw new InvalidOperationException($"Cannot remove the active signing key '{keyId}'; activate another key first.");
            var entries = new KeyValuePair<string, IAAuthSigner>[current.Entries.Length - 1];
            Array.Copy(current.Entries, 0, entries, 0, index);
            Array.Copy(current.Entries, index + 1, entries, index, entries.Length - index);
            _snapshot = current with { Entries = entries };
            return true;
        }
    }

    /// <summary>Look up a published key by <c>kid</c>.</summary>
    public bool TryGetSigner(string keyId, [NotNullWhen(true)] out IAAuthSigner? signer)
    {
        var current = _snapshot;
        var index = current.IndexOf(keyId);
        signer = index < 0 ? null : current.Entries[index].Value;
        return signer is not null;
    }

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, IAAuthSigner>> GetEnumerator() =>
        ((IEnumerable<KeyValuePair<string, IAAuthSigner>>)_snapshot.Entries).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    private void Upsert(string keyId, IAAuthSigner signer, bool replace)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(signer);
        lock (_gate)
        {
            var current = _snapshot;
            var index = current.IndexOf(keyId);
            KeyValuePair<string, IAAuthSigner>[] entries;
            if (index >= 0)
            {
                if (!replace) throw new ArgumentException($"A signing key with kid '{keyId}' is already present.", nameof(keyId));
                entries = (KeyValuePair<string, IAAuthSigner>[])current.Entries.Clone();
                entries[index] = new(keyId, signer);
            }
            else
            {
                entries = [.. current.Entries, new(keyId, signer)];
            }
            _snapshot = current with { Entries = entries };
        }
    }

    private sealed record Snapshot(KeyValuePair<string, IAAuthSigner>[] Entries, string? ActiveKeyId)
    {
        public int IndexOf(string keyId) =>
            Array.FindIndex(Entries, entry => string.Equals(entry.Key, keyId, StringComparison.Ordinal));

        public (string KeyId, IAAuthSigner Signer)? ResolveActiveOrDefault()
        {
            if (ActiveKeyId is null)
                return Entries.Length == 0 ? null : (Entries[0].Key, Entries[0].Value);
            var index = IndexOf(ActiveKeyId);
            return index < 0 ? null : (Entries[index].Key, Entries[index].Value);
        }

        public (string KeyId, IAAuthSigner Signer) ResolveActive() =>
            ResolveActiveOrDefault() ?? throw new InvalidOperationException(ActiveKeyId is null
                ? "The signing key set is empty."
                : $"The active signing key '{ActiveKeyId}' has not been added.");
    }
}
