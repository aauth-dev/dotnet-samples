using System.Text.Json.Nodes;
using AAuth.Server;

namespace MockAccessServer.Policy;

/// <summary>
/// Pure-.NET stand-in for the Keycloak policy, encoding the same demo rules
/// locally so the four-party flow runs without Docker (the default provider;
/// keeps <c>make e2e</c>/CI dependency-free).
///
/// Demo policy (mirrors WhoAmI <c>/jwt</c> vs <c>/jwt/admin</c>):
/// <list type="bullet">
///   <item>any verified agent may obtain the base <c>whoami</c> scope;</item>
///   <item>an elevated scope (<c>whoami:admin</c>) is granted only when the
///   PS-asserted claims carry the <c>whoami-admin</c> role.</item>
/// </list>
///
/// When <c>requireConsent</c> is set (from <c>AccessServer:RequireConsent</c>)
/// the stub returns <see cref="AccessDecisionKind.NeedsInteraction"/> for every
/// request it would otherwise allow — mirroring Keycloak's interactive
/// login/consent round-trip so that, from the agent's perspective, the stub and
/// Keycloak behave identically (same 202 → interaction URL → poll → mint); only
/// the interaction URL differs (the stub's own consent screen vs Keycloak).
/// </summary>
public sealed class StubAccessPolicy : IAccessPolicy
{
    /// <summary>The role a principal must hold to be granted an elevated scope.</summary>
    public const string AdminRole = "whoami-admin";

    private readonly IReadOnlyList<string> _requiredClaims;
    private readonly bool _requireConsent;

    /// <summary>
    /// Create the stub policy. <paramref name="requiredClaims"/> (from
    /// <c>AccessServer:RequireClaims</c>) lets the demo exercise the
    /// §Claims Required push: when set, the policy returns
    /// <see cref="AccessDecisionKind.NeedsClaims"/> until the Person Server has
    /// pushed every named claim. Empty (the default) preserves the
    /// allow/deny behaviour. When <paramref name="requireConsent"/> (from
    /// <c>AccessServer:RequireConsent</c>) is set, an otherwise-allowed request
    /// returns <see cref="AccessDecisionKind.NeedsInteraction"/> so the user
    /// approves at the AS consent screen, just like the Keycloak path.
    /// </summary>
    public StubAccessPolicy(
        IReadOnlyList<string>? requiredClaims = null, bool requireConsent = false)
    {
        _requiredClaims = requiredClaims ?? [];
        _requireConsent = requireConsent;
    }

    public Task<AccessDecision> EvaluateAsync(
        AccessPolicyRequest request, CancellationToken cancellationToken = default)
    {
        // §Claims Required: if the AS is configured to need identity claims it
        // does not yet hold, ask the PS to push them before deciding.
        var missing = MissingClaims(request.Claims);
        if (missing.Count > 0)
        {
            return Task.FromResult(AccessDecision.NeedsClaims(missing));
        }

        // An elevated (admin) scope requires the admin role; the base scope is
        // open to any verified agent.
        if (IsElevatedScope(request.Scope) && !HasRole(request.Claims, AdminRole))
        {
            return Task.FromResult(AccessDecision.Deny(
                $"scope '{request.Scope}' requires the '{AdminRole}' role"));
        }

        // Interactive consent: park the (otherwise-allowed) decision so the
        // user approves at the AS consent screen. Once approved the pending
        // entry flips to Allowed and the poll mints — the policy is not
        // re-evaluated, so this never loops.
        if (_requireConsent)
        {
            return Task.FromResult(AccessDecision.NeedsInteraction());
        }

        return Task.FromResult(AccessDecision.Allow());
    }

    private List<string> MissingClaims(JsonObject? claims)
    {
        var missing = new List<string>();
        foreach (var name in _requiredClaims)
        {
            if (claims?[name] is null)
            {
                missing.Add(name);
            }
        }
        return missing;
    }

    private static bool IsElevatedScope(string scope) =>
        scope.Contains(':', StringComparison.Ordinal);

    private static bool HasRole(JsonObject? claims, string role)
    {
        if (claims?["roles"] is not JsonArray roles)
        {
            return false;
        }

        foreach (var node in roles)
        {
            if (node is JsonValue value
                && value.TryGetValue(out string? r)
                && string.Equals(r, role, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
