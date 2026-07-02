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

    /// <summary>
    /// A mission-gate entry awaiting the agent's clarification answer
    /// (§Clarification Chat). The next poll re-emits <c>requirement=clarification</c>.
    /// </summary>
    AwaitingClarification,

    /// <summary>
    /// The agent withdrew the request (DELETE on the pending URL). The next poll
    /// returns <c>410 Gone</c>.
    /// </summary>
    Withdrawn,
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

    /// <summary>
    /// When set, this entry's out-of-scope decision (and any clarification
    /// round-trip) is driven by <c>IMissionTokenConsent</c> on each poll, rather
    /// than by an out-of-band <see cref="MarkAllowed"/>/<see cref="MarkDenied"/>.
    /// </summary>
    public bool MissionGate { get; set; }

    /// <summary>The agent's justification (#aauth-prompt), captured for re-review.</summary>
    public string? Prompt { get; set; }

    /// <summary>The agent's declared capabilities (#aauth-capabilities), captured for re-review.</summary>
    public IReadOnlyList<string>? Capabilities { get; set; }

    /// <summary>The pending clarification question (§Clarification Chat), when awaiting an answer.</summary>
    public string? ClarificationQuestion { get; set; }

    /// <summary>Optional clarification timeout in seconds (#requirement-clarification).</summary>
    public int? ClarificationTimeout { get; set; }

    /// <summary>Optional discrete clarification choices (#requirement-clarification).</summary>
    public IReadOnlyList<string>? ClarificationOptions { get; set; }

    /// <summary>The agent's clarification answers so far, oldest first.</summary>
    public List<string> ClarificationAnswers { get; } = [];

    /// <summary>
    /// Set once a mission-gate entry's out-of-scope verdict has been recorded in
    /// the mission log, so repeat polls return the cached result idempotently
    /// without re-logging.
    /// </summary>
    public bool MissionResolved { get; set; }

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

    /// <summary>
    /// Optional host-owned JSON details rendered by the interaction page before a
    /// pending decision resolves. The SDK stores this opaquely.
    /// </summary>
    public JsonNode? ConsentDetails { get; set; }

    /// <summary>
    /// Optional host-owned interactive verdict for <see cref="ConsentDetails"/>.
    /// <see langword="null"/> means no local verdict has been recorded yet.
    /// </summary>
    public bool? ConsentDecision { get; set; }

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

    /// <summary>The Access Server audience for a deferred four-party federation.</summary>
    public string? FederatedAccessServerAudience { get; set; }

    /// <summary>The verified resource token to submit to the Access Server.</summary>
    public string? FederatedResourceToken { get; set; }

    /// <summary>The agent token to submit to the Access Server.</summary>
    public string? FederatedAgentToken { get; set; }

    /// <summary>The optional upstream token to submit to the Access Server.</summary>
    public string? FederatedUpstreamToken { get; set; }

    /// <summary>
    /// Runtime-only agent confirmation key used to verify AS auth-token delivery.
    /// </summary>
    public IAAuthKey? FederatedAgentKey { get; set; }

    /// <summary>True once the PS has started the PS→AS federation task.</summary>
    public bool FederationStarted { get; set; }

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
        ArgumentException.ThrowIfNullOrEmpty(resourceUrl);
        ArgumentException.ThrowIfNullOrEmpty(scope);
        ArgumentException.ThrowIfNullOrEmpty(agentId);
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
