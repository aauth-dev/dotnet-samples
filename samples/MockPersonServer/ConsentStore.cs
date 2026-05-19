using System.Collections.Concurrent;

namespace MockPersonServer;

/// <summary>
/// Demo-only in-memory consent store. Records approved
/// <c>(agent, resource, scope)</c> triples. A production PS persists
/// consent records in a database keyed by user identity.
/// </summary>
public sealed class ConsentStore
{
    private readonly ConcurrentDictionary<(string Agent, string Resource, string Scope), byte> _consented
        = new();

    public bool IsConsented(string agent, string resource, string scope)
        => _consented.ContainsKey((agent, resource, scope));

    public void Grant(string agent, string resource, string scope)
        => _consented[(agent, resource, scope)] = 1;

    public void Revoke(string agent, string resource, string scope)
        => _consented.TryRemove((agent, resource, scope), out _);
}

/// <summary>
/// In-memory store of pending token requests awaiting user consent.
/// Each entry corresponds to one <c>POST /token</c> that returned
/// <c>202 Accepted</c>. The agent polls <c>GET /pending/{id}</c> until
/// the user approves consent (or denies — see <see cref="Deny(string)"/>
/// — or the entry is abandoned).
/// </summary>
public sealed class PendingStore
{
    public sealed record Entry(
        string Id,
        string Agent,
        string Resource,
        string Scope,
        string ResourceTokenJwt,
        AAuth.Crypto.AAuthKey AgentConfirmationKey)
    {
        /// <summary>
        /// True once the user has explicitly denied this request. The
        /// pending endpoint returns <c>403 access_denied</c> in that case
        /// so the agent can distinguish denial from "unknown / expired".
        /// </summary>
        public bool Denied { get; internal set; }
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    public Entry Add(string agent, string resource, string scope, string resourceTokenJwt,
        AAuth.Crypto.AAuthKey agentConfirmationKey)
    {
        var id = Guid.NewGuid().ToString("N");
        var entry = new Entry(id, agent, resource, scope, resourceTokenJwt, agentConfirmationKey);
        _entries[id] = entry;
        return entry;
    }

    public Entry? Get(string id)
        => _entries.TryGetValue(id, out var e) ? e : null;

    /// <summary>
    /// Mark an entry as denied. Unlike <see cref="Remove(string)"/>, the
    /// entry stays in the store so the agent's poller gets a
    /// deterministic <c>403 access_denied</c> rather than an ambiguous
    /// <c>404</c>.
    /// </summary>
    public bool Deny(string id)
    {
        if (!_entries.TryGetValue(id, out var entry)) { return false; }
        entry.Denied = true;
        return true;
    }

    public void Remove(string id)
        => _entries.TryRemove(id, out _);
}
