using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AAuth.Server;
using AAuth.Server.CallChaining;
using Microsoft.IdentityModel.Tokens;

namespace Concierge;

/// <summary>
/// Demo-only in-memory store of interaction-chained requests the Concierge
/// has deferred back to its caller (AAuth protocol §Interaction Chaining).
/// </summary>
/// <remarks>
/// <para>When the Concierge's downstream token exchange returns
/// <c>202 requirement=interaction</c>, the Concierge (which has no user of
/// its own) cannot relay the interaction. Instead it persists an entry here,
/// re-emits its <em>own</em> <c>202</c> to the caller with
/// <c>Location=/pending/{id}</c> and an intermediary interaction URL. That URL
/// redirects the browser to the downstream PS interaction; the caller polls
/// <c>GET /pending/{id}</c> until consent resolves.</para>
/// <para>A production intermediary would persist these durably and expire them
/// on a timer; this demo store is in-memory and never GCs.</para>
/// </remarks>
public sealed class PendingStore
{
    public sealed record Entry(
        string Id,
        string UpstreamToken,
        ChainedInteractionEntry Interaction,
        string DownstreamBase,
        string DownstreamPath,
        string PendingPrefix)
    {
        public DateTimeOffset ExpiresAt { get; } = DateTimeOffset.FromUnixTimeSeconds(
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(UpstreamToken.Split('.')[1]))!["exp"]!.GetValue<long>());
        public DeferredState Lifecycle { get; } = new();
        public bool Matches(string? upstreamToken) => string.Equals(UpstreamToken, upstreamToken, StringComparison.Ordinal);
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    /// <summary>
    /// Create a pending entry capturing the upstream auth token (used to
    /// re-drive the chained call on each poll) and the SDK-owned chained
    /// interaction. <paramref name="downstreamBase"/> +
    /// <paramref name="downstreamPath"/> are the downstream resource origin and
    /// path re-driven on each poll (e.g. Calendar <c>/events</c> or the
    /// mission-aware Trips <c>/trips</c>); <paramref name="pendingPrefix"/>
    /// is the caller-facing poll route prefix (e.g. <c>/pending</c> or
    /// <c>/mission-pending</c>).
    /// </summary>
    public Entry Add(
        string upstreamToken,
        ChainedInteractionEntry interaction,
        string downstreamBase = "http://localhost:5001",
        string downstreamPath = "/events",
        string pendingPrefix = "/pending")
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt.AddHours(1) <= DateTimeOffset.UtcNow) _entries.TryRemove(pair.Key, out _);
        var entry = new Entry(
            interaction.Id, upstreamToken, interaction, downstreamBase, downstreamPath, pendingPrefix);
        _entries[interaction.Id] = entry;
        return entry;
    }

    public Entry? Get(string id)
        => _entries.TryGetValue(id, out var e) ? e : null;

    public void Remove(string id)
        => _entries.TryRemove(id, out _);

    /// <summary>Drop all pending entries back to the empty baseline.</summary>
    public void Clear() => _entries.Clear();
}
