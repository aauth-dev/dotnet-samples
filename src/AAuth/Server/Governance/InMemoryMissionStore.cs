using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;

namespace AAuth.Server.Governance;

/// <summary>
/// In-memory <see cref="IMissionStore"/> for development and testing. NOT
/// production-grade — state is lost on restart and there is no distributed
/// support.
/// </summary>
public sealed class InMemoryMissionStore : IMissionStore
{
    private readonly ConcurrentDictionary<(string PersonServer, string S256), StoredMission> _missions = new();

    /// <inheritdoc/>
    public Task SaveAsync(StoredMission mission, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(mission);
        ValidateStoredMission(mission);
        _missions.AddOrUpdate((mission.PersonServer, mission.S256), mission, (_, existing) => mission with
        {
            // A replacement never revives a terminated mission or extends its expiry.
            State = existing.State == MissionState.Terminated ? MissionState.Terminated : mission.State,
            TerminationReason = existing.State == MissionState.Terminated
                ? existing.TerminationReason
                : mission.TerminationReason,
            ExpiresAt = Earliest(existing.ExpiresAt, mission.ExpiresAt),
        });
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<StoredMission?> GetAsync(string personServer, string s256, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrEmpty(personServer);
        System.ArgumentException.ThrowIfNullOrEmpty(s256);
        _missions.TryGetValue((personServer, s256), out var mission);
        return Task.FromResult(mission);
    }

    /// <inheritdoc/>
    public Task TerminateAsync(string personServer, string s256, string terminationReason, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrWhiteSpace(personServer);
        System.ArgumentException.ThrowIfNullOrWhiteSpace(s256);
        if (string.IsNullOrWhiteSpace(terminationReason))
            throw new System.ArgumentException("A mission termination reason is required.", nameof(terminationReason));
        var key = (personServer, s256);
        while (_missions.TryGetValue(key, out var existing) && existing.State != MissionState.Terminated)
        {
            var terminated = existing with
            {
                State = MissionState.Terminated,
                TerminationReason = terminationReason,
            };
            if (_missions.TryUpdate(key, terminated, existing)) break;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrEmpty(s256);
        var mission = _missions.Values.FirstOrDefault(m => m.S256 == s256);
        return Task.FromResult(mission);
    }

    /// <inheritdoc/>
    public Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrEmpty(s256);
        foreach (var (key, existing) in _missions.Where(pair => pair.Value.S256 == s256).ToArray())
        {
            if (state == MissionState.Terminated)
            {
                _ = TerminateAsync(key.PersonServer, key.S256,
                    AAuthConstants.MissionTerminationReasons.Administrative, ct);
            }
        }
        return Task.CompletedTask;
    }

    private static System.DateTimeOffset? Earliest(System.DateTimeOffset? a, System.DateTimeOffset? b)
        => a is null ? b : b is null ? a : a < b ? a : b;

    private static void ValidateStoredMission(StoredMission mission)
    {
        if (mission.State == MissionState.Terminated && string.IsNullOrWhiteSpace(mission.TerminationReason))
            throw new System.ArgumentException("A terminated mission requires a termination reason.", nameof(mission));
        if (mission.State == MissionState.Active && !string.IsNullOrWhiteSpace(mission.TerminationReason))
            throw new System.ArgumentException("An active mission cannot carry a termination reason.", nameof(mission));
    }
}
