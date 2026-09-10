using System.Collections.Concurrent;

namespace MockPersonServer;

/// <summary>
/// Demo-only in-memory consent store. Records approved
/// <c>(agent, resource, scope)</c> triples. A production PS persists
/// consent records in a database keyed by user identity.
/// </summary>
public sealed class ConsentStore
{
    private readonly ConcurrentDictionary<(string Agent, string Resource, string Scope, string? Account, string? Key), byte> _consented
        = new();

    public bool IsConsented(string agent, string resource, string scope, string? account = null, string? key = null)
        => _consented.ContainsKey((agent, resource, scope, account, key));

    public void Grant(string agent, string resource, string scope, string? account = null, string? key = null)
        => _consented[(agent, resource, scope, account, key)] = 1;

    public void Revoke(string agent, string resource, string scope, string? account = null, string? key = null)
        => _consented.TryRemove((agent, resource, scope, account, key), out _);

    /// <summary>Wipe all consent records back to the empty baseline.</summary>
    public void Clear() => _consented.Clear();
}
