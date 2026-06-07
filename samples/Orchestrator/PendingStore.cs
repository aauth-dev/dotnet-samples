using System.Collections.Concurrent;

namespace Orchestrator;

/// <summary>
/// Demo-only in-memory store of interaction-chained requests the Orchestrator
/// has deferred back to its caller (AAuth protocol §Interaction Chaining).
/// </summary>
/// <remarks>
/// <para>When the Orchestrator's downstream token exchange returns
/// <c>202 requirement=interaction</c>, the Orchestrator (which has no user of
/// its own) cannot relay the interaction. Instead it persists an entry here,
/// re-emits its <em>own</em> <c>202</c> to the caller with
/// <c>Location=/pending/{id}</c>, and passes through the downstream PS's
/// interaction <c>url</c> + <c>code</c>. The caller relays the user to the PS
/// and polls <c>GET /pending/{id}</c>; each poll re-drives the chained call
/// with the stored upstream auth token until consent resolves.</para>
/// <para>A production intermediary would persist these durably and expire them
/// on a timer; this demo store is in-memory and never GCs.</para>
/// </remarks>
public sealed class PendingStore
{
    public sealed record Entry(
        string Id,
        string UpstreamToken,
        string InteractionUrl,
        string InteractionCode,
        string DownstreamPath,
        string PendingPrefix);

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    /// <summary>
    /// Create a pending entry capturing the upstream auth token (used to
    /// re-drive the chained call on each poll) and the pass-through PS
    /// interaction <c>url</c> + <c>code</c>. <paramref name="downstreamPath"/>
    /// is the downstream resource path re-driven on each poll (e.g. <c>/jwt</c>
    /// or the mission-aware <c>/jwt/mission</c>); <paramref name="pendingPrefix"/>
    /// is the caller-facing poll route prefix (e.g. <c>/pending</c> or
    /// <c>/mission-pending</c>).
    /// </summary>
    public Entry Add(
        string upstreamToken,
        string interactionUrl,
        string interactionCode,
        string downstreamPath = "/jwt",
        string pendingPrefix = "/pending")
    {
        var id = Guid.NewGuid().ToString("N");
        var entry = new Entry(
            id, upstreamToken, interactionUrl, interactionCode, downstreamPath, pendingPrefix);
        _entries[id] = entry;
        return entry;
    }

    public Entry? Get(string id)
        => _entries.TryGetValue(id, out var e) ? e : null;

    public void Remove(string id)
        => _entries.TryRemove(id, out _);

    /// <summary>Drop all pending entries back to the empty baseline.</summary>
    public void Clear() => _entries.Clear();
}
