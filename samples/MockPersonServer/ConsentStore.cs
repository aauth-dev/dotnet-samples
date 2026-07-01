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

    /// <summary>Wipe all consent records back to the empty baseline.</summary>
    public void Clear() => _consented.Clear();
}
