using System;
using System.Collections.Concurrent;

namespace AAuth.Server;

/// <summary>A parked resource-managed interaction awaiting the user's approval.</summary>
public sealed class InteractionPendingEntry
{
    public string? Account { get; init; }
    /// <summary>The interaction code presented to the user.</summary>
    public required string Code { get; init; }

    /// <summary>The scope the interaction grants on approval.</summary>
    public required string Scope { get; init; }

    /// <summary>The agent's JWK thumbprint captured when the interaction was parked.</summary>
    public required string AgentJkt { get; init; }
    public string? OwnerIssuer { get; set; }
    public string? OwnerAgent { get; set; }
    public BrowserInteraction Browser { get; init; } = new();
    public DeferredState Lifecycle { get; } = new();
    public bool Denied { get; set; }
    internal bool TokenConsumed { get; set; }

    /// <summary>When this pending interaction (and its code) expires.</summary>
    public DateTimeOffset Expiry { get; init; }

    // Written by the consent page on one request, read by the poll endpoint on
    // another — volatile gives the cross-thread write/read release/acquire
    // visibility a plain auto-property would not guarantee.
    private volatile bool _approved;

    /// <summary>Whether the user has approved this interaction.</summary>
    public bool Approved { get => _approved; set => _approved = value; }
}

/// <summary>
/// Park/poll store for the resource-managed (two-party) interaction flow
/// (§Resource-Managed Authorization). The SDK owns code generation, parking,
/// single-use, and expiry; the resource owns only its consent page, which records
/// the user's decision via <see cref="Approve"/>.
/// </summary>
public interface IInteractionPendingStore
{
    /// <summary>
    /// Park a new interaction for <paramref name="scope"/> bound to
    /// <paramref name="agentJkt"/>, generating a spec-conformant code with the
    /// given time-to-live.
    /// </summary>
    InteractionPendingEntry Park(string scope, string agentJkt, TimeSpan ttl, string? account = null);

    /// <summary>Look up a parked interaction by code (normalized); null if unknown or expired.</summary>
    InteractionPendingEntry? Get(string code);

    /// <summary>Record the user's approval (called by the resource's consent page).</summary>
    bool Approve(string code);

    /// <summary>
    /// Atomically consume an approved interaction: if it exists, is unexpired, and
    /// is approved, remove it and return it (single-use); otherwise return
    /// <see langword="false"/> without removing a still-pending entry. Only one
    /// concurrent caller wins, so an approved interaction issues at most one token.
    /// </summary>
    bool TryConsume(string code, out InteractionPendingEntry entry);

    /// <summary>Remove a parked interaction once it has been consumed.</summary>
    void Remove(string code);
}

/// <summary>
/// In-memory <see cref="IInteractionPendingStore"/>. Enforces the code-level spec
/// MUSTs (entropy via <see cref="AAuthInteractionCode"/>, single-use via
/// <see cref="Remove"/>, expiry); rate-limiting code-validation attempts at the
/// consent URL is a deployment control (gateway / the resource's consent handler).
/// </summary>
public sealed class InMemoryInteractionPendingStore : IInteractionPendingStore
{
    private readonly ConcurrentDictionary<string, InteractionPendingEntry> _entries = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public InteractionPendingEntry Park(string scope, string agentJkt, TimeSpan ttl, string? account = null)
    {
        AAuth.Tokens.AccountBinding.Validate(account);
        ArgumentException.ThrowIfNullOrEmpty(scope);
        ArgumentException.ThrowIfNullOrEmpty(agentJkt);
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));
        foreach (var pair in _entries)
            if (pair.Value.Expiry.AddHours(1) <= DateTimeOffset.UtcNow) _entries.TryRemove(pair.Key, out _);
        var browser = new BrowserInteraction();
        var entry = new InteractionPendingEntry
        {
            Code = browser.Code,
            Browser = browser,
            Scope = scope,
            AgentJkt = agentJkt,
            Account = account,
            Expiry = DateTimeOffset.UtcNow.Add(ttl),
        };
        _entries[AAuthInteractionCode.Normalize(entry.Code)] = entry;
        return entry;
    }

    /// <inheritdoc/>
    public InteractionPendingEntry? Get(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        foreach (var pair in _entries)
            if (pair.Value.Expiry.AddHours(1) <= DateTimeOffset.UtcNow) _entries.TryRemove(pair.Key, out _);
        var key = AAuthInteractionCode.Normalize(code);
        if (!_entries.TryGetValue(key, out var entry))
        {
            return null;
        }
        return entry;
    }

    /// <inheritdoc/>
    public bool Approve(string code)
    {
        var entry = Get(code);
        if (entry is null)
        {
            return false;
        }
        entry.Lifecycle.Gate.Wait();
        try
        {
            if (entry.Expiry <= DateTimeOffset.UtcNow || entry.Lifecycle.Delivered || entry.Lifecycle.Cancelled
                || entry.Lifecycle.InvalidCode || entry.Denied || entry.Approved) return false;
            entry.Approved = true;
            return true;
        }
        finally { entry.Lifecycle.Gate.Release(); }
    }

    /// <inheritdoc/>
    public bool TryConsume(string code, out InteractionPendingEntry entry)
    {
        entry = null!;
        var existing = Get(code);
        if (existing is null)
        {
            return false;
        }
        // TryRemove is atomic: only the first concurrent caller wins, so an
        // approved interaction issues at most one token (single-use).
        lock (existing)
        {
            if (!existing.Approved || existing.TokenConsumed || existing.Denied
                || existing.Expiry <= DateTimeOffset.UtcNow || existing.Lifecycle.Cancelled
                || existing.Lifecycle.InvalidCode) return false;
            existing.TokenConsumed = true;
            entry = existing;
            return true;
        }
    }

    /// <inheritdoc/>
    public void Remove(string code) =>
        _entries.TryRemove(AAuthInteractionCode.Normalize(code), out _);
}
