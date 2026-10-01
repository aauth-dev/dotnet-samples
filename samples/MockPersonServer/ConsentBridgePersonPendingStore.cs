using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Person;
using AAuth.Tokens;

namespace MockPersonServer;

/// <summary>
/// Bridges the demo's <c>(agent, resource, scope)</c>-keyed <see cref="ConsentStore"/>
/// (driven by the unchanged <c>/admin/consent</c> + <c>/interaction</c> surfaces)
/// into the SDK's id-keyed <see cref="IPersonPendingStore"/>. On read, a parked
/// non-mission three-party entry flips to allowed — with the demo identity — once
/// consent is recorded, so the agent's next poll mints. Mission-gate entries are
/// left untouched: the SDK resolves those through <see cref="ScriptMissionTokenConsent"/>.
/// </summary>
public sealed class ConsentBridgePersonPendingStore : IPersonPendingStore
{
    private readonly InMemoryPersonPendingStore _inner = new();
    private readonly ConsentStore _consent;
    private readonly ConsentRegistry _registry;
    private readonly IReadOnlyList<string>? _demoRoles;
    private readonly IReadOnlyList<string>? _demoGroups;

    public ConsentBridgePersonPendingStore(
        ConsentStore consent, ConsentRegistry registry, IReadOnlyList<string>? demoRoles, IReadOnlyList<string>? demoGroups)
    {
        _consent = consent;
        _registry = registry;
        _demoRoles = demoRoles;
        _demoGroups = demoGroups;
    }

    public PersonPendingEntry Add(
        string resourceUrl, string scope, string agentId, IAAuthKey? agentConfirmationKey,
        DateTimeOffset agentTokenExpiresAt,
        string? missionS256 = null,
        DateTimeOffset? authorizationExpiresAt = null)
        => _inner.Add(resourceUrl, scope, agentId, agentConfirmationKey, agentTokenExpiresAt,
            missionS256, authorizationExpiresAt);

    public PersonPendingEntry? Get(string id)
    {
        var entry = _inner.Get(id);
        if (entry is null) return null;
        entry.Lifecycle.Gate.Wait();
        try
        {
            // Non-mission three-party entry awaiting consent (PS mints): flip to
            // allowed once the demo ConsentStore records it.
            if (entry is { MissionGate: false, MissionS256: null, AgentConfirmationKey: not null, Status: PersonPendingStatus.Pending }
                && !entry.Lifecycle.Delivered && !entry.Lifecycle.Cancelled && !entry.Lifecycle.InvalidCode
                && entry.PendingExpiresAt > DateTimeOffset.UtcNow
                && _consent.IsConsented(entry.ConsentAgentId, entry.ResourceUrl, entry.Scope, entry.Account, entry.ResourceKeyThumbprint))
            {
                entry.PersonKey = SampleIdentityClaimsAsserter.DemoPersonKey;
                entry.Subject = SampleIdentityClaimsAsserter.DirectedSubject(entry.ResourceUrl);
                entry.Tenant = null;
                entry.Roles = _demoRoles;
                entry.Groups = _demoGroups;
                entry.AdditionalClaims = null;
                entry.Status = PersonPendingStatus.Allowed;
                _registry.MarkDecided(entry.Id, ConsentDecider.Admin);
            }
            return entry;
        }
        finally { entry.Lifecycle.Gate.Release(); }
    }

    public PersonPendingEntry? GetByCode(string code) => _inner.GetByCode(code);

    public void MarkAllowed(
        string id, AAuthPersonKey personKey, string? subject = null, string? tenant = null,
        IReadOnlyList<string>? roles = null, IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
        => _inner.MarkAllowed(id, personKey, subject, tenant, roles, groups, additionalClaims);

    public void MarkDenied(string id, string reason) => _inner.MarkDenied(id, reason);
}
