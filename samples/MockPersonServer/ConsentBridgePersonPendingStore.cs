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
    private const string Subject = "pairwise-sub";

    private readonly InMemoryPersonPendingStore _inner = new();
    private readonly ConsentStore _consent;
    private readonly IReadOnlyList<string> _demoRoles;
    private readonly IReadOnlyList<string> _demoGroups;

    public ConsentBridgePersonPendingStore(
        ConsentStore consent, IReadOnlyList<string> demoRoles, IReadOnlyList<string> demoGroups)
    {
        _consent = consent;
        _demoRoles = demoRoles;
        _demoGroups = demoGroups;
    }

    public PersonPendingEntry Add(
        string resourceUrl, string scope, string agentId, IAAuthKey? agentConfirmationKey,
        JsonObject? upstreamAct = null, MissionClaim? mission = null)
        => _inner.Add(resourceUrl, scope, agentId, agentConfirmationKey, upstreamAct, mission);

    public PersonPendingEntry? Get(string id)
    {
        var entry = _inner.Get(id);
        // Non-mission three-party entry awaiting consent (PS mints): flip to
        // allowed once the demo ConsentStore records it.
        if (entry is { MissionGate: false, Mission: null, AgentConfirmationKey: not null, Status: PersonPendingStatus.Pending }
            && _consent.IsConsented(entry.AgentId, entry.ResourceUrl, entry.Scope))
        {
            var isAdmin = SampleIdentityClaimsAsserter.IsAdminAgent(entry.AgentId);
            _inner.MarkAllowed(id, Subject, tenant: null,
                roles: isAdmin ? _demoRoles : null, groups: isAdmin ? _demoGroups : null);
        }
        return _inner.Get(id);
    }

    public void MarkAllowed(
        string id, string subject, string? tenant = null,
        IReadOnlyList<string>? roles = null, IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
        => _inner.MarkAllowed(id, subject, tenant, roles, groups, additionalClaims);

    public void MarkDenied(string id, string reason) => _inner.MarkDenied(id, reason);
}
