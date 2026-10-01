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
/// request in either issuance mode, the <see cref="ConsentStore"/> gate). The mission
/// out-of-scope decision is a separate concern owned by
/// <see cref="ScriptMissionTokenConsent"/>; here a mission request only asserts
/// identity after the SDK's shared mission gate. A production PS resolves the signed-in user's directory entry.
/// </summary>
public sealed class SampleIdentityClaimsAsserter : IIdentityClaimsAsserter
{
    private const string DemoTenant = "demo-tenant";
    public static readonly AAuthPersonKey DemoPersonKey = new("isolated-demo-person");
    public static string DirectedSubject(string resource) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes("isolated-demo-person\0" + resource))).ToLowerInvariant();

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

    /// <summary>
    /// The exact agent identifiers the demo treats as "admin" (AgentConsole). Matching is
    /// exact and ordinal: a prefix test would let <c>aauth:demo@attacker.example</c> claim
    /// the demo roles. A production PS resolves the bound principal's directory membership.
    /// </summary>
    public static IReadOnlySet<(string Issuer, string AgentId)> AdminAgents { get; } =
        new HashSet<(string, string)> { ("https://ap.example", "aauth:demo@ap.example") };

    /// <summary>Demo "admin" agents receive the demo roles/groups.</summary>
    public static bool IsAdminAgent(string agentIssuer, string agentId) => AdminAgents.Contains((agentIssuer, agentId));

    public Task<IdentityAssertion> AssertAsync(
        IdentityAssertionRequest request, CancellationToken cancellationToken = default)
    {
        var isAdmin = IsAdminAgent(request.AgentIssuer, request.AgentId);
        var roles = isAdmin ? _demoRoles : null;
        var groups = isAdmin ? _demoGroups : null;
        var subject = DirectedSubject(request.ResourceUrl);
        // Person token request: the demo PS acts for one person, so it names them
        // at once. The resource decides what identity alone is worth.
        if (request.PersonTokenRequest)
            return Task.FromResult(IdentityAssertion.Assert(DemoPersonKey, subject));
        if (request.MissionS256 is null && _requireConsent
            && !_consent.IsConsented(request.AgentId, request.ResourceUrl, request.Scope, request.Account, request.AgentKeyThumbprint))
            return Task.FromResult(IdentityAssertion.NeedsConsent(DemoPersonKey));

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
                DemoPersonKey, subject, tenant: DemoTenant, roles: roles, groups: groups, additionalClaims: additional));
        }

        // Mission request: identity only — the mission gate decision is the
        // ScriptMissionTokenConsent seam's job. No PS consent gate here.
        if (request.MissionS256 is not null)
        {
            return Task.FromResult(IdentityAssertion.Assert(DemoPersonKey, subject, roles: roles, groups: groups));
        }

        // Non-mission three-party: gate on the demo ConsentStore (driven by the
        // unchanged /admin/consent + /interaction browser surfaces).
        if (!_requireConsent || _consent.IsConsented(request.AgentId, request.ResourceUrl, request.Scope, request.Account, request.AgentKeyThumbprint))
        {
            return Task.FromResult(IdentityAssertion.Assert(DemoPersonKey, subject, roles: roles, groups: groups));
        }
        return Task.FromResult(IdentityAssertion.NeedsConsent(DemoPersonKey));
    }
}
