using AAuth.Person;
using AAuth.Server;

namespace MockPersonServer;

/// <summary>What a PS consent request asks the person to decide.</summary>
public enum ConsentKind
{
    Token,
    PersonToken,
    MissionToken,
    MissionCreation,
    Permission,
    FederatedConsent,
    AccessServerInteraction,
}

public enum ConsentStatus
{
    Pending,
    Approved,
    Denied,
    Expired,
    Withdrawn,
    Delivered,
}

public enum ConsentDecider
{
    Dashboard,
    Link,
    Admin,
    Script,
    Policy,
}

/// <summary>
/// One PS-parked consent request. It holds the live pending entry, so status and
/// the current interaction code are derived rather than copied.
/// </summary>
public sealed class ConsentRecord
{
    private readonly MissionPolicyStore _policy;

    internal ConsentRecord(PersonPendingEntry entry, MissionPolicyStore policy)
    {
        PersonEntry = entry;
        _policy = policy;
        CreatedAt = entry.CreatedAt;
    }

    internal ConsentRecord(MissionPendingEntry entry, MissionPolicyStore policy)
    {
        MissionEntry = entry;
        _policy = policy;
        CreatedAt = entry.CreatedAt;
    }

    public PersonPendingEntry? PersonEntry { get; }
    public MissionPendingEntry? MissionEntry { get; }
    public string Id => PersonEntry?.Id ?? MissionEntry!.Id;
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt => PersonEntry?.PendingExpiresAt ?? MissionEntry!.ExpiresAt;
    public DeferredState Lifecycle => PersonEntry?.Lifecycle ?? MissionEntry!.Lifecycle;
    public BrowserInteraction Browser => PersonEntry?.Browser ?? MissionEntry!.Browser;
    public string AgentId => PersonEntry?.ConsentAgentId ?? MissionEntry!.AgentId;
    public string? Resource => PersonEntry?.ResourceUrl ?? MissionEntry!.Resource;
    public string? Scope => PersonEntry is { } entry ? (entry.PersonToken ? null : entry.Scope) : MissionEntry!.Scope;
    public string? Account => PersonEntry?.Account;
    public string? Action => MissionEntry?.Action;

    /// <summary>The Access Server's interaction URL when the PS relays one; not PS-hosted.</summary>
    public string? ExternalInteractionUrl => PersonEntry is { InteractionCode: not null } entry ? entry.InteractionUrl : null;

    public string? MissionS256 => PersonEntry is { } entry ? entry.MissionS256
        : string.IsNullOrEmpty(MissionEntry!.S256) ? null : MissionEntry.S256;

    public string? MissionDescription => MissionEntry?.Proposal?.Description
        ?? (MissionS256 is { } s256 ? _policy.Describe(s256) : null);

    public ConsentDecider? DecidedBy { get; private set; }
    public DateTimeOffset? DecidedAt { get; private set; }

    public ConsentKind Kind => MissionEntry is { } mission
        ? mission.Kind switch
        {
            MissionPendingKind.Mission => ConsentKind.MissionCreation,
            MissionPendingKind.Token => ConsentKind.MissionToken,
            _ => ConsentKind.Permission,
        }
        : PersonEntry switch
        {
            { FederationConsent: not null } => ConsentKind.FederatedConsent,
            { InteractionCode: not null } => ConsentKind.AccessServerInteraction,
            { PersonToken: true } => ConsentKind.PersonToken,
            { MissionGate: true } => ConsentKind.MissionToken,
            _ => ConsentKind.Token,
        };

    /// <summary>
    /// Whether the person sees this request. Resource-interaction hops and a
    /// four-party federation that has not asked the PS for consent are not
    /// PS consent requests (yet).
    /// </summary>
    public bool IsListed => PersonEntry is not { } entry
        || (!entry.AwaitingResourceInteraction
            && (entry.AgentConfirmationKey is not null || entry.PersonToken
                || entry.FederationConsent is not null || entry.InteractionCode is not null));

    public ConsentStatus Status
    {
        get
        {
            var now = DateTimeOffset.UtcNow;
            if (MissionEntry is { } mission)
            {
                if (mission.Lifecycle.Cancelled) return ConsentStatus.Withdrawn;
                if (mission.Decision is false) return ConsentStatus.Denied;
                if (mission.Decision is true)
                    return mission.Lifecycle.Delivered ? ConsentStatus.Delivered : ConsentStatus.Approved;
                return mission.ExpiresAt <= now || mission.Lifecycle.InvalidCode || mission.Lifecycle.Delivered
                    ? ConsentStatus.Expired : ConsentStatus.Pending;
            }
            var entry = PersonEntry!;
            if (entry.Status == PersonPendingStatus.Withdrawn || entry.Lifecycle.Cancelled) return ConsentStatus.Withdrawn;
            if (entry.Status == PersonPendingStatus.Denied) return ConsentStatus.Denied;
            if (entry.FederationConsent is { Task.IsCompletedSuccessfully: true } consent
                && consent.Task.Result.Kind != IdentityAssertionKind.Assert) return ConsentStatus.Denied;
            if (entry.Lifecycle.Delivered) return ConsentStatus.Delivered;
            if (entry.Status == PersonPendingStatus.Allowed || entry.FederationConsent is { Task.IsCompleted: true })
                return ConsentStatus.Approved;
            return entry.PendingExpiresAt <= now || entry.Lifecycle.InvalidCode
                ? ConsentStatus.Expired : ConsentStatus.Pending;
        }
    }

    /// <summary>Whether the PS dashboard may decide this request now (Q9: PS-hosted only).</summary>
    public bool IsDecidable => IsListed && Status == ConsentStatus.Pending && Kind != ConsentKind.AccessServerInteraction
        && (PersonEntry is not { } entry || entry.Status == PersonPendingStatus.Pending)
        && (Kind != ConsentKind.FederatedConsent || PersonEntry!.AwaitingFederationConsent);

    /// <summary>Who decided, falling back to the automated decider when nobody recorded one.</summary>
    public ConsentDecider? Decider => DecidedBy ?? (Status is ConsentStatus.Approved or ConsentStatus.Denied or ConsentStatus.Delivered
        ? Kind is ConsentKind.MissionToken or ConsentKind.MissionCreation or ConsentKind.Permission
            ? ConsentDecider.Script : ConsentDecider.Policy
        : null);

    internal void MarkDecided(ConsentDecider by)
    {
        if (DecidedBy is not null) return;
        DecidedBy = by;
        DecidedAt = DateTimeOffset.UtcNow;
    }
}

/// <summary>
/// In-memory, capped history of every PS-parked consent request (Q8). Cleared by
/// <c>/admin/reset</c>.
/// </summary>
public sealed class ConsentRegistry(MissionPolicyStore policy)
{
    public const int Capacity = 500;
    private readonly LinkedList<ConsentRecord> _records = new();
    private readonly Dictionary<string, LinkedListNode<ConsentRecord>> _byId = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    public void Register(PersonPendingEntry entry) => Add(new ConsentRecord(entry, policy));

    public void Register(MissionPendingEntry entry) => Add(new ConsentRecord(entry, policy));

    public ConsentRecord? Find(string id)
    {
        lock (_lock) return _byId.TryGetValue(id, out var node) ? node.Value : null;
    }

    /// <summary>Read-only lookup of a pending request by its current code; never consumes it.</summary>
    public ConsentRecord? FindPendingByCode(string code)
    {
        var normalized = AAuth.Headers.InteractionCode.Normalize(code);
        if (string.IsNullOrEmpty(normalized)) return null;
        return Snapshot().FirstOrDefault(record => record.IsDecidable && record.Browser.Code == normalized);
    }

    /// <summary>Listed records, newest first.</summary>
    public IReadOnlyList<ConsentRecord> Snapshot()
    {
        lock (_lock) return _records.Where(record => record.IsListed).Reverse().ToArray();
    }

    public void MarkDecided(string id, ConsentDecider by) => Find(id)?.MarkDecided(by);

    public void Clear()
    {
        lock (_lock)
        {
            _records.Clear();
            _byId.Clear();
        }
    }

    private void Add(ConsentRecord record)
    {
        lock (_lock)
        {
            if (_byId.ContainsKey(record.Id)) return;
            _byId[record.Id] = _records.AddLast(record);
            while (_records.Count > Capacity)
            {
                _byId.Remove(_records.First!.Value.Id);
                _records.RemoveFirst();
            }
        }
    }
}
