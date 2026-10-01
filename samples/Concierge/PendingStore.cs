using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AAuth.Server;
using AAuth.Server.CallChaining;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Concierge;

/// <summary>
/// Demo-only in-memory store of interaction-chained requests the Concierge
/// has deferred back to its caller (AAuth protocol §Interaction Chaining).
/// </summary>
/// <remarks>
/// <para>When the Concierge's downstream token exchange returns
/// <c>202 requirement=interaction</c>, the Concierge (which has no user of
/// its own) keeps polling the downstream pending URL in the background
/// (<see cref="AAuthChainedOperation{TResult}"/>) and stores an entry here. It
/// answers the caller with its <em>own</em> <c>202</c>, <c>Location=/pending/{id}</c>
/// and an intermediary interaction URL that redirects the browser to the
/// downstream interaction. The caller's polls read the operation's state; they
/// never re-send the downstream request.</para>
/// <para>A production intermediary would persist these durably and expire them
/// on a timer; this demo store is in-memory.</para>
/// </remarks>
public sealed class PendingStore
{
    public sealed class Entry
    {
        private readonly object _gate = new();
        private readonly HashSet<string> _codes = new(StringComparer.Ordinal);
        private ChainedInteractionEntry _interaction;
        private long _version;

        internal Entry(string upstreamToken, ChainedInteractionEntry interaction, string pendingPrefix,
            AAuthChainedOperation<IResult>? operation, long interactionVersion)
        {
            UpstreamToken = upstreamToken;
            PendingPrefix = pendingPrefix;
            Operation = operation;
            _interaction = interaction;
            _codes.Add(interaction.Code);
            _version = interactionVersion;
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(
                JsonNode.Parse(Base64UrlEncoder.DecodeBytes(upstreamToken.Split('.')[1]))!["exp"]!.GetValue<long>());
        }

        public string Id => _interaction.Id;
        public string UpstreamToken { get; }
        public string PendingPrefix { get; }

        /// <summary>The background downstream work, or null when nothing is running.</summary>
        public AAuthChainedOperation<IResult>? Operation { get; }

        public DateTimeOffset ExpiresAt { get; }
        public DeferredState Lifecycle { get; } = new();

        /// <summary>
        /// The Concierge's current interaction. When the downstream asked for a different
        /// interaction (for example an AS step after PS consent), it is re-keyed with a new code,
        /// atomically with its downstream redirect target.
        /// </summary>
        public ChainedInteractionEntry Interaction
        {
            get
            {
                lock (_gate)
                {
                    if (Operation?.Interaction is { } latest && latest.Version > _version)
                    {
                        _interaction = AAuthChainedInteractions.Rekey(_interaction, latest.Downstream);
                        _codes.Add(_interaction.Code);
                        _version = latest.Version;
                    }
                    return _interaction;
                }
            }
        }

        /// <summary>Any code this entry issued stays valid and leads to the latest downstream step.</summary>
        public bool MatchesCode(string? code)
        {
            if (string.IsNullOrEmpty(code)) return false;
            lock (_gate)
                foreach (var issued in _codes)
                    if (AAuth.Server.AAuthInteractionCode.Matches(issued, code)) return true;
            return false;
        }

        public bool Matches(string? upstreamToken) => string.Equals(UpstreamToken, upstreamToken, StringComparison.Ordinal);
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    /// <summary>
    /// Create a pending entry capturing the upstream auth token (the caller must
    /// re-present it on every poll), the SDK-owned chained interaction and the
    /// running downstream <paramref name="operation"/>. <paramref name="pendingPrefix"/>
    /// is the caller-facing poll route prefix (e.g. <c>/pending</c> or <c>/mission-pending</c>).
    /// <paramref name="interactionVersion"/> is the version of the operation's interaction that
    /// <paramref name="interaction"/> was parked from; a newer one re-keys the entry.
    /// </summary>
    public Entry Add(
        string upstreamToken,
        ChainedInteractionEntry interaction,
        string pendingPrefix = "/pending",
        AAuthChainedOperation<IResult>? operation = null,
        long interactionVersion = 0)
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt.AddHours(1) <= DateTimeOffset.UtcNow) _entries.TryRemove(pair.Key, out _);
        var entry = new Entry(upstreamToken, interaction, pendingPrefix, operation, interactionVersion);
        _entries[interaction.Id] = entry;
        return entry;
    }

    public Entry? Get(string id)
        => _entries.TryGetValue(id, out var e) ? e : null;

    public void Remove(string id)
        => _entries.TryRemove(id, out _);

    /// <summary>Drop all pending entries back to the empty baseline.</summary>
    public void Clear()
    {
        foreach (var entry in _entries.Values) entry.Operation?.Cancel();
        _entries.Clear();
    }
}
