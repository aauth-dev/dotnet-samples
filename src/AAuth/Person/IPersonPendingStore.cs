using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Person;

/// <summary>
/// Stores in-flight Person Server token decisions awaiting an interactive user
/// review/consent round-trip (§Interaction), and — in the four-party
/// (federated) flow — the background PS→AS federation result. The
/// <c>MapAAuthPersonServer</c> host parks the mint inputs here when the asserter
/// defers, and resumes (mint or deny) when the agent polls the pending URL. The
/// PS counterpart to <c>AAuth.Access.IAccessPendingStore</c>.
/// </summary>
public interface IPersonPendingStore
{
    /// <summary>Park a new pending decision and return the created entry.</summary>
    PersonPendingEntry Add(
        string resourceUrl,
        string scope,
        string agentId,
        IAAuthKey? agentConfirmationKey,
        JsonObject? upstreamAct = null,
        MissionClaim? mission = null);

    /// <summary>Look up a pending entry by id, or <see langword="null"/>.</summary>
    PersonPendingEntry? Get(string id);

    /// <summary>
    /// Mark the entry allowed with the asserted identity the next poll mints.
    /// The host's interaction page calls this once the user has consented.
    /// </summary>
    void MarkAllowed(
        string id,
        string subject,
        string? tenant = null,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null);

    /// <summary>Mark the entry denied with a reason.</summary>
    void MarkDenied(string id, string reason);
}

/// <summary>The lifecycle state of a <see cref="PersonPendingEntry"/>.</summary>
public enum PersonPendingStatus
{
    /// <summary>Awaiting the user review/consent (or background federation).</summary>
    Pending,

    /// <summary>Approved — the next poll mints (or returns) the auth token.</summary>
    Allowed,

    /// <summary>Denied — the next poll returns <c>403 denied</c>.</summary>
    Denied,
}

/// <summary>A parked Person Server token decision.</summary>
public sealed class PersonPendingEntry
{
    /// <summary>Opaque pending id (path segment of the <c>Location</c> URL).</summary>
    public required string Id { get; init; }

    /// <summary>The resource URL the auth token will be audienced to.</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The verified agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// The agent's confirmation key (<c>cnf.jwk</c> binding) — set for the
    /// three-party path where the PS mints. <see langword="null"/> for the
    /// four-party path where the AS mints and the PS only relays.
    /// </summary>
    public IAAuthKey? AgentConfirmationKey { get; init; }

    /// <summary>Optional upstream <c>act</c> context for call chaining.</summary>
    public JsonObject? UpstreamAct { get; init; }

    /// <summary>The mission context governing the request, if any.</summary>
    public MissionClaim? Mission { get; init; }

    /// <summary>The entry's lifecycle state.</summary>
    public PersonPendingStatus Status { get; set; }

    /// <summary>The directed <c>sub</c> the asserter supplied on approval.</summary>
    public string? Subject { get; set; }

    /// <summary>The asserted tenant claim, if any.</summary>
    public string? Tenant { get; set; }

    /// <summary>The asserted role claims, if any.</summary>
    public IReadOnlyList<string>? Roles { get; set; }

    /// <summary>The asserted group claims, if any.</summary>
    public IReadOnlyList<string>? Groups { get; set; }

    /// <summary>Any further asserted identity claims, if any.</summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; set; }

    /// <summary>The denial reason when <see cref="Status"/> is Denied.</summary>
    public string? DenyReason { get; set; }

    /// <summary>
    /// The AS-issued auth token, set when the four-party federation completes
    /// successfully. When present, the next poll returns it verbatim (the AS
    /// minted it; the PS does not re-mint).
    /// </summary>
    public string? AuthToken { get; set; }

    /// <summary>The AS interaction URL to relay to the agent (four-party).</summary>
    public string? InteractionUrl { get; set; }

    /// <summary>The AS interaction code to relay to the agent (four-party).</summary>
    public string? InteractionCode { get; set; }

    /// <summary>An error code surfaced by a failed federation, if any.</summary>
    public string? Error { get; set; }

    /// <summary>The HTTP status to surface for <see cref="Error"/>, if any.</summary>
    public int? ErrorStatus { get; set; }

    /// <summary>A <c>Location</c> to surface alongside <see cref="Error"/> (e.g. payment), if any.</summary>
    public string? ErrorLocation { get; set; }

    /// <summary>
    /// Completes when the four-party federation produces its first answer
    /// (an AS interaction to relay, or a terminal result). Runtime-only.
    /// </summary>
    public TaskCompletionSource FirstAnswer { get; }
        = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>When the entry was parked. Drives in-memory TTL eviction.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Process-wide in-memory <see cref="IPersonPendingStore"/>. Suitable for a
/// single-instance demo/sample; a production PS would persist entries with a
/// TTL. Entries are evicted once they exceed <see cref="Ttl"/> (lazily, on each
/// <see cref="Add"/>/<see cref="Get"/>) so the dictionary does not grow without
/// bound.
/// </summary>
public sealed class InMemoryPersonPendingStore : IPersonPendingStore
{
    /// <summary>How long a parked entry is retained before it is evicted.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, PersonPendingEntry> _entries = new();

    /// <inheritdoc />
    public PersonPendingEntry Add(
        string resourceUrl,
        string scope,
        string agentId,
        IAAuthKey? agentConfirmationKey,
        JsonObject? upstreamAct = null,
        MissionClaim? mission = null)
    {
        Sweep();
        var entry = new PersonPendingEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            ResourceUrl = resourceUrl,
            Scope = scope,
            AgentId = agentId,
            AgentConfirmationKey = agentConfirmationKey,
            UpstreamAct = upstreamAct,
            Mission = mission,
            Status = PersonPendingStatus.Pending,
        };
        _entries[entry.Id] = entry;
        return entry;
    }

    /// <inheritdoc />
    public PersonPendingEntry? Get(string id)
    {
        Sweep();
        return _entries.TryGetValue(id, out var entry) ? entry : null;
    }

    /// <inheritdoc />
    public void MarkAllowed(
        string id,
        string subject,
        string? tenant = null,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Subject = subject;
            entry.Tenant = tenant;
            entry.Roles = roles;
            entry.Groups = groups;
            entry.AdditionalClaims = additionalClaims;
            entry.Status = PersonPendingStatus.Allowed;
        }
    }

    /// <inheritdoc />
    public void MarkDenied(string id, string reason)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Status = PersonPendingStatus.Denied;
            entry.DenyReason = reason;
        }
    }

    /// <summary>Remove all entries (test helper).</summary>
    public void Clear() => _entries.Clear();

    /// <summary>Evict entries older than <see cref="Ttl"/>.</summary>
    private void Sweep()
    {
        var cutoff = DateTimeOffset.UtcNow - Ttl;
        foreach (var kv in _entries)
        {
            if (kv.Value.CreatedAt < cutoff)
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }
    }
}
