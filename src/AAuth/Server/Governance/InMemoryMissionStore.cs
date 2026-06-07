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
        _missions[mission.S256] = mission;
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
        if (_missions.TryGetValue(s256, out var existing))
        {
            _missions[s256] = existing with { State = state };
        }
        return Task.CompletedTask;
    }
}
