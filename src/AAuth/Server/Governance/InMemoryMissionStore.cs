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
    private readonly ConcurrentDictionary<string, StoredMission> _missions = new();

    /// <inheritdoc/>
    public Task SaveAsync(StoredMission mission, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(mission);
        _missions.AddOrUpdate(mission.S256, mission, (_, existing) => mission with
        {
            // A replacement never revives a terminated mission or extends its expiry.
            State = existing.State == MissionState.Terminated ? MissionState.Terminated : mission.State,
            ExpiresAt = Earliest(existing.ExpiresAt, mission.ExpiresAt),
        });
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrEmpty(s256);
        _missions.TryGetValue(s256, out var mission);
        return Task.FromResult(mission);
    }

    /// <inheritdoc/>
    public Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default)
    {
        System.ArgumentException.ThrowIfNullOrEmpty(s256);
        while (_missions.TryGetValue(s256, out var existing)
            && existing.State != MissionState.Terminated
            && existing.State != state
            && !_missions.TryUpdate(s256, existing with { State = state }, existing))
        {
        }
        return Task.CompletedTask;
    }

    private static System.DateTimeOffset? Earliest(System.DateTimeOffset? a, System.DateTimeOffset? b)
        => a is null ? b : b is null ? a : a < b ? a : b;
}
