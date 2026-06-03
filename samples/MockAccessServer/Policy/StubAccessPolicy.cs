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
/// The stub is non-interactive — it never returns <c>NeedsInteraction</c>;
/// the interactive login/consent round-trip is exercised by
/// <c>KeycloakAccessPolicy</c>.
/// </summary>
public sealed class StubAccessPolicy : IAccessPolicy
{
    /// <summary>The role a principal must hold to be granted an elevated scope.</summary>
    public const string AdminRole = "whoami-admin";

    private readonly IReadOnlyList<string> _requiredClaims;

    /// <summary>
    /// Create the stub policy. <paramref name="requiredClaims"/> (from
    /// <c>AccessServer:RequireClaims</c>) lets the demo exercise the
    /// §Claims Required push: when set, the policy returns
    /// <see cref="AccessDecisionKind.NeedsClaims"/> until the Person Server has
    /// pushed every named claim. Empty (the default) preserves the
    /// non-interactive allow/deny behaviour.
    /// </summary>
    public StubAccessPolicy(IReadOnlyList<string>? requiredClaims = null)
        => _requiredClaims = requiredClaims ?? [];

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
