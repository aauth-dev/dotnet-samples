using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Person;

namespace MockPersonServer;

/// <summary>
/// The MockPS identity/consent decision — the SDK's <see cref="IIdentityClaimsAsserter"/>
/// seam. Supplies the demo principal's directed identity (and, for a non-mission
/// three-party request, the <see cref="ConsentStore"/> gate). The mission
/// out-of-scope decision is a separate concern owned by
/// <see cref="ScriptMissionTokenConsent"/>; here a mission request only asserts
/// identity. A production PS resolves the signed-in user's directory entry.
/// </summary>
public sealed class SampleIdentityClaimsAsserter : IIdentityClaimsAsserter
{
    private const string Subject = "pairwise-sub";
    private const string DemoTenant = "demo-tenant";

    private readonly ConsentStore _consent;
    private readonly bool _requireConsent;
    private readonly IReadOnlyList<string> _demoRoles;
    private readonly IReadOnlyList<string> _demoGroups;
    private readonly IReadOnlyDictionary<string, string> _demoUserClaims;

    public SampleIdentityClaimsAsserter(
        ConsentStore consent,
        bool requireConsent,
        IReadOnlyList<string> demoRoles,
        IReadOnlyList<string> demoGroups,
        IReadOnlyDictionary<string, string> demoUserClaims)
    {
        _consent = consent;
        _requireConsent = requireConsent;
        _demoRoles = demoRoles;
        _demoGroups = demoGroups;
        _demoUserClaims = demoUserClaims;
    }

    /// <summary>Demo "admin" agents (id <c>aauth:demo@…</c>) receive the demo roles/groups.</summary>
    public static bool IsAdminAgent(string agentId) =>
        agentId.StartsWith("aauth:demo@", StringComparison.Ordinal);

    public Task<IdentityAssertion> AssertAsync(
        IdentityAssertionRequest request, CancellationToken cancellationToken = default)
    {
        var isAdmin = IsAdminAgent(request.AgentId);
        var roles = isAdmin ? _demoRoles : null;
        var groups = isAdmin ? _demoGroups : null;

        // Four-party §Claims Required push: the AS asked for specific claim names.
        // Assert the demo principal's claims; the host projects the requested subset.
        if (request.RequiredClaims is not null)
        {
            var additional = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
            foreach (var (name, value) in _demoUserClaims)
            {
                additional[name] = value;
            }
            return Task.FromResult(IdentityAssertion.Assert(
                Subject, tenant: DemoTenant, roles: roles, groups: groups, additionalClaims: additional));
        }

        // Mission request: identity only — the mission gate decision is the
        // ScriptMissionTokenConsent seam's job. No PS consent gate here.
        if (request.Mission is not null)
        {
            return Task.FromResult(IdentityAssertion.Assert(Subject, roles: roles, groups: groups));
        }

        // Non-mission three-party: gate on the demo ConsentStore (driven by the
        // unchanged /admin/consent + /interaction browser surfaces).
        if (!_requireConsent || _consent.IsConsented(request.AgentId, request.ResourceUrl, request.Scope))
        {
            return Task.FromResult(IdentityAssertion.Assert(Subject, roles: roles, groups: groups));
        }
        return Task.FromResult(IdentityAssertion.NeedsConsent());
    }
}
