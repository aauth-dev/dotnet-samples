using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;

namespace AAuth.Server.Governance;

/// <summary>
/// A mission as persisted by the PS: the verbatim approval blob bytes (so the
/// <c>s256</c> remains verifiable) plus its lifecycle state (§Mission Approval,
/// §Mission Management).
/// </summary>
/// <param name="S256">The mission identity — base64url(SHA-256(blob)).</param>
/// <param name="Approver">HTTPS URL of the approver (the PS).</param>
/// <param name="Agent">The agent identifier the mission was approved for.</param>
/// <param name="Blob">The exact approval response body bytes, stored verbatim.</param>
public sealed record StoredMission(
    string S256,
    string Approver,
    string Agent,
    ReadOnlyMemory<byte> Blob)
{
    /// <summary>The mission lifecycle state (§Mission Management). Defaults to active.</summary>
    public MissionState State { get; init; } = MissionState.Active;
}

/// <summary>
/// PS-side persistence seam for missions (§Mission Approval, §Mission
/// Management). The SDK provides the contract and an in-memory default
/// (<see cref="InMemoryMissionStore"/>); a production PS swaps in durable storage.
/// </summary>
public interface IMissionStore
{
    /// <summary>Persist (or replace) a mission keyed by its <c>s256</c>.</summary>
    Task SaveAsync(StoredMission mission, CancellationToken ct = default);

    /// <summary>Look up a mission by its <c>s256</c>. Returns <see langword="null"/> when absent.</summary>
    Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default);

    /// <summary>
    /// Transition a mission to <paramref name="state"/> (e.g. on completion or
    /// revocation). No-op when the mission is absent.
    /// </summary>
    Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default);
}
