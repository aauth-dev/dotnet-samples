using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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
        DateTimeOffset agentTokenExpiresAt,
        string? missionS256 = null,
        DateTimeOffset? authorizationExpiresAt = null);

    /// <summary>Look up a pending entry by id, or <see langword="null"/>.</summary>
    PersonPendingEntry? Get(string id);
    PersonPendingEntry? GetByCode(string code);

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

/// <summary>
/// Observes each request the Person Server parks for the person (§Deferred Responses), for
/// example to list it on a consent dashboard. Register it in DI, keyed by the Person Server name
/// or unkeyed; every registered observer sees every entry of that server, whichever
/// <see cref="IPersonPendingStore"/> holds it. The entry is still being filled in when observed:
/// read its state when it is needed, not at <see cref="OnParked"/>.
/// </summary>
public interface IPersonPendingObserver
{
    /// <summary>Called once, right after <paramref name="entry"/> is parked.</summary>
    void OnParked(PersonPendingEntry entry);
}

internal sealed class ObservedPersonPendingStore(IPersonPendingStore inner, IReadOnlyList<IPersonPendingObserver> observers)
    : IPersonPendingStore
{
    public PersonPendingEntry Add(string resourceUrl, string scope, string agentId, IAAuthKey? agentConfirmationKey,
        DateTimeOffset agentTokenExpiresAt, string? missionS256 = null, DateTimeOffset? authorizationExpiresAt = null)
    {
        var entry = inner.Add(resourceUrl, scope, agentId, agentConfirmationKey, agentTokenExpiresAt, missionS256,
            authorizationExpiresAt);
        foreach (var observer in observers) observer.OnParked(entry);
        return entry;
    }

    public PersonPendingEntry? Get(string id) => inner.Get(id);
    public PersonPendingEntry? GetByCode(string code) => inner.GetByCode(code);

    public void MarkAllowed(string id, string subject, string? tenant = null, IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? groups = null, IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
        => inner.MarkAllowed(id, subject, tenant, roles, groups, additionalClaims);

    public void MarkDenied(string id, string reason) => inner.MarkDenied(id, reason);
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

    public string? OwnerIssuer { get; set; }
    public string? OwnerSubject { get; set; }
    public string? OwnerKeyThumbprint { get; set; }
    public IReadOnlyList<AAuth.Server.TokenKey> SourceTokens { get; set; } = [];
    public AAuth.Server.DeferredState Lifecycle { get; } = new();
    public AAuth.Server.BrowserInteraction Browser { get; } = new();
    public string? ResourceKeyThumbprint { get; set; }
    public string? ResourceAudience { get; set; }
    public string? ResourceToken { get; set; }
    public JsonObject? ResourceContext { get; set; }
    public string? Account => AccountBinding.Read(ResourceContext);
    public UpstreamTokenValidationResult? UpstreamAuthorization { get; set; }
    internal PersonResourceInteraction? ResourceInteraction { get; set; }
    internal Func<Microsoft.AspNetCore.Http.HttpContext, Task<Microsoft.AspNetCore.Http.IResult>>? ResumeAuthorization { get; set; }
    public bool AwaitingResourceInteraction => ResourceInteraction is { Complete: false, Error: null };
    public int ClarificationRounds { get; set; }
    public DateTimeOffset? ClarificationDeadline { get; set; }
    public System.Threading.CancellationTokenSource FederationCancellation { get; } = new();
    public TaskCompletionSource<AAuth.Agent.ClarificationResponse>? FederationAnswer { get; set; }
    public TaskCompletionSource<IdentityAssertion>? FederationConsent { get; set; }
    internal TaskCompletionSource<bool>? FederationMissionConsent { get; set; }
    public bool AwaitingFederationConsent => FederationConsent is { Task.IsCompleted: false };
    public IReadOnlyList<string>? RequiredIdentityClaims { get; set; }
    public string ConsentAgentId => OwnerSubject ?? AgentId;

    /// <summary>The resource URL the auth token will be audienced to.</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope.</summary>
    public required string Scope { get; set; }

    /// <summary>The verified agent identifier.</summary>
    public required string AgentId { get; init; }

    public required DateTimeOffset AgentTokenExpiresAt { get; init; }

    public DateTimeOffset? AuthorizationExpiresAt { get; init; }

    public DateTimeOffset ExpiresAt => AuthorizationExpiresAt is { } expiry && expiry < AgentTokenExpiresAt
        ? expiry : AgentTokenExpiresAt;

    public DateTimeOffset PendingExpiresAt => new[] { ExpiresAt, CreatedAt.AddMinutes(10),
        ClarificationDeadline ?? ExpiresAt }.Min();

    /// <summary>
    /// The agent's confirmation key (<c>cnf.jwk</c> binding) — set for the
    /// three-party path where the PS mints. <see langword="null"/> for the
    /// four-party path where the AS mints and the PS only relays.
    /// </summary>
    public IAAuthKey? AgentConfirmationKey { get; init; }

    /// <summary><see langword="true"/> when the entry resolves to a person token rather than an auth token.</summary>
    public bool PersonToken { get; set; }

    /// <summary>The verified directed <c>sub</c> the minted auth token carries (from the resource token).</summary>
    public string? PersonSubject { get; set; }

    /// <summary>The verified <c>tenant</c> the minted token carries.</summary>
    public string? PersonTenant { get; set; }

    /// <summary>The <c>presented_token</c> of an auth token request, forwarded to an AS in four-party.</summary>
    public string? PresentedToken { get; set; }

    /// <summary>The mission governing the request (<c>mission_s256</c>), if any.</summary>
    public string? MissionS256 { get; set; }

    /// <summary>
    /// When set, this entry's out-of-scope decision (and any clarification
    /// round-trip) is driven by <c>IMissionTokenConsent</c> on each poll, rather
    /// than by an out-of-band <see cref="MarkAllowed"/>/<see cref="MarkDenied"/>.
    /// </summary>
    public bool MissionGate { get; set; }

    /// <summary>The OIDC <c>prompt</c> value from the token request, captured for re-review.</summary>
    public string? Prompt { get; set; }

    /// <summary>The agent-asserted content of the request (§Consent Presentation), captured for re-review.</summary>
    public AgentAssertedContent? AgentAsserted { get; set; }

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
        DateTimeOffset agentTokenExpiresAt,
        string? missionS256 = null,
        DateTimeOffset? authorizationExpiresAt = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceUrl);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        Sweep();
        var entry = new PersonPendingEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            ResourceUrl = resourceUrl,
            Scope = scope,
            AgentId = agentId,
            AgentTokenExpiresAt = agentTokenExpiresAt,
            AuthorizationExpiresAt = authorizationExpiresAt,
            AgentConfirmationKey = agentConfirmationKey,
            MissionS256 = missionS256,
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

    public PersonPendingEntry? GetByCode(string code)
    {
        Sweep();
        var normalized = AAuth.Headers.InteractionCode.Normalize(code);
        return _entries.Values.FirstOrDefault(entry => entry.Browser.Code == normalized);
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
        if (Get(id) is { } entry)
        {
            entry.Lifecycle.Gate.Wait();
            try
            {
                if (entry.Lifecycle.Delivered || entry.Lifecycle.Cancelled || entry.PendingExpiresAt <= DateTimeOffset.UtcNow
                    || entry.Status != PersonPendingStatus.Pending) return;
                entry.Subject = subject;
                entry.Tenant = tenant;
                entry.Roles = roles;
                entry.Groups = groups;
                entry.AdditionalClaims = additionalClaims;
                if (entry.FederationConsent is { } consent)
                    consent.TrySetResult(IdentityAssertion.Assert(subject, tenant, roles, groups, additionalClaims));
                else
                    entry.Status = PersonPendingStatus.Allowed;
            }
            finally { entry.Lifecycle.Gate.Release(); }
        }
    }

    /// <inheritdoc />
    public void MarkDenied(string id, string reason)
    {
        if (Get(id) is { } entry)
        {
            entry.Lifecycle.Gate.Wait();
            try
            {
                if (entry.Lifecycle.Delivered || entry.Lifecycle.Cancelled || entry.PendingExpiresAt <= DateTimeOffset.UtcNow
                    || entry.Status is PersonPendingStatus.Allowed or PersonPendingStatus.Denied or PersonPendingStatus.Withdrawn) return;
                entry.Status = PersonPendingStatus.Denied;
                entry.DenyReason = reason;
                entry.FederationConsent?.TrySetResult(IdentityAssertion.Deny(reason));
            }
            finally { entry.Lifecycle.Gate.Release(); }
        }
    }

    /// <summary>Remove all entries (test helper).</summary>
    public void Clear() => _entries.Clear();

    /// <summary>Evict entries older than <see cref="Ttl"/>.</summary>
    private void Sweep()
    {
        var cutoff = DateTimeOffset.UtcNow - Ttl - TimeSpan.FromHours(1);
        foreach (var kv in _entries)
        {
            if (kv.Value.CreatedAt < cutoff)
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }
    }
}
