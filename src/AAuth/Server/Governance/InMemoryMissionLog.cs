using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Governance;

/// <summary>
/// In-memory <see cref="IMissionLog"/> for development and testing. Preserves
/// append order per mission. NOT production-grade — state is lost on restart.
/// </summary>
public sealed class InMemoryMissionLog : IMissionLog
{
    private readonly object _gate = new();
    private readonly Dictionary<string, List<MissionLogEntry>> _entries = new();

    /// <inheritdoc/>
    public Task AppendAsync(MissionLogEntry entry, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_gate)
        {
            if (!_entries.TryGetValue(entry.S256, out var list))
            {
                list = new List<MissionLogEntry>();
                _entries[entry.S256] = list;
            }
            list.Add(entry);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<MissionLogEntry>> ReadAsync(string s256, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        lock (_gate)
        {
            IReadOnlyList<MissionLogEntry> snapshot = _entries.TryGetValue(s256, out var list)
                ? list.ToArray()
                : Array.Empty<MissionLogEntry>();
            return Task.FromResult(snapshot);
        }
    }

    /// <inheritdoc/>
    public Task<bool> HasPriorConsentAsync(string s256, string resource, string scope, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        ArgumentException.ThrowIfNullOrEmpty(resource);
        ArgumentException.ThrowIfNullOrEmpty(scope);
        lock (_gate)
        {
            if (!_entries.TryGetValue(s256, out var list))
            {
                return Task.FromResult(false);
            }
            foreach (var entry in list)
            {
                if (entry.Kind == MissionLogEntryKind.Token
                    && entry.Granted == true
                    && string.Equals(entry.Resource, resource, StringComparison.Ordinal)
                    && string.Equals(entry.Scope, scope, StringComparison.Ordinal))
                {
                    return Task.FromResult(true);
                }
            }
            return Task.FromResult(false);
        }
    }
}
