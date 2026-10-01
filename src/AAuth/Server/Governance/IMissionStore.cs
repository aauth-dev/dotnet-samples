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
/// <param name="PersonServer">HTTPS identifier of the PS that approved the mission.</param>
/// <param name="Agent">The agent identifier the mission was approved for.</param>
/// <param name="Blob">The exact approval response body bytes, stored verbatim.</param>
public sealed record StoredMission(
    string S256,
    string PersonServer,
    string Agent,
    ReadOnlyMemory<byte> Blob)
{
    /// <summary>The mission lifecycle state (§Mission Management). Defaults to active.</summary>
    public MissionState State { get; init; } = MissionState.Active;

    /// <summary>
    /// The approved mission's <c>expires_at</c>, when set. Tokens carrying this
    /// mission's <c>mission_s256</c> MUST NOT outlive it, and the mission is no
    /// longer active once it passes.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// Opaque §Mission Management reason recorded when <see cref="State"/> is
    /// <see cref="MissionState.Terminated"/>. SDK stores use
    /// <see cref="AAuthConstants.MissionTerminationReasons"/> values.
    /// </summary>
    public string? TerminationReason { get; init; }
}

/// <summary>
/// PS-side persistence seam for missions (§Mission Approval, §Mission
/// Management). The SDK provides the contract and an in-memory default
/// (<see cref="InMemoryMissionStore"/>); a production PS swaps in durable storage.
/// </summary>
public interface IMissionStore
{
    /// <summary>
    /// Persist (or replace) a mission keyed by its <c>s256</c>. Replacing a
    /// terminated mission MUST keep it terminated, and a replacement MUST NOT
    /// extend a stored <see cref="StoredMission.ExpiresAt"/> (§Mission Management).
    /// </summary>
    Task SaveAsync(StoredMission mission, CancellationToken ct = default);

    /// <summary>
    /// Look up a mission by the spec identity pair <c>(PersonServer, s256)</c>.
    /// Returns <see langword="null"/> when absent. Stores MUST make absent,
    /// wrong-agent and wrong-PS lookup paths observably equivalent for SDK
    /// endpoint callers (§Mission Endpoint Errors).
    /// </summary>
    Task<StoredMission?> GetAsync(string personServer, string s256, CancellationToken ct = default);

    /// <summary>
    /// Permanently terminate a mission with <paramref name="terminationReason"/>.
    /// No-op when absent; idempotent when already terminated; preserves the first
    /// non-empty reason and never revives a terminated mission (§Mission
    /// Management).
    /// </summary>
    Task TerminateAsync(string personServer, string s256, string terminationReason, CancellationToken ct = default);

    /// <summary>Look up a mission by its <c>s256</c>. Returns <see langword="null"/> when absent.</summary>
    Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default);

    /// <summary>
    /// Transition a mission to <paramref name="state"/> (e.g. on completion or
    /// revocation). No-op when the mission is absent. A terminated mission MUST
    /// NOT return to active, even under concurrent transitions (§Mission Management).
    /// </summary>
    Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default);
}
