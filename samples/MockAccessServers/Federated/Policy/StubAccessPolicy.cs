using System.Text.Json.Nodes;
using AAuth.Access;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;

namespace MockAccessServer.Policy;

/// <summary>
/// Pure-.NET stand-in for the Keycloak policy, encoding the same demo rules
/// locally so the four-party flow runs without Docker (the default provider;
/// keeps <c>make e2e</c>/CI dependency-free).
///
/// Demo policy (mirrors Wallet <c>/wallet</c> vs <c>/wallet/charge</c>):
/// <list type="bullet">
///   <item>any verified agent may obtain the base <c>wallet.read</c> scope;</item>
///   <item>the elevated <c>wallet.charge</c> scope is granted only when the
///   person carries the <c>wallet.payer</c> role. Roles are identity claims
///   about the person, so the AS asks the PS for them (§Claims Required,
///   <c>requirement=claims</c>) rather than inferring them from the agent.</item>
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
    /// <summary>The role a principal must hold to be granted the elevated scope.</summary>
    public const string AdminRole = "wallet.payer";

    /// <summary>The elevated scope that requires <see cref="AdminRole"/>.</summary>
    public const string ElevatedScope = "wallet.charge";

    private readonly IReadOnlyList<string> _requiredClaims;
    private readonly bool _requireConsent;
    private readonly WalletPolicyRules? _walletRules;

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
        IReadOnlyList<string>? requiredClaims = null, bool requireConsent = false, WalletPolicyRules? walletRules = null)
    {
        _requiredClaims = requiredClaims ?? [];
        _requireConsent = requireConsent;
        _walletRules = walletRules;
    }

    public Task<AccessDecision> EvaluateAsync(
        AccessPolicyRequest request, CancellationToken cancellationToken = default)
    {
        if (_walletRules?.Evaluate(request) is { } walletDecision) return Task.FromResult(walletDecision);
        var elevated = IsElevatedScope(request.Scope);

        // §Claims Required: before the PS has pushed anything, ask for every claim
        // the decision needs: the configured ones, plus `roles` for the elevated scope.
        if (request.Claims is null)
        {
            var needed = elevated ? _requiredClaims.Append("roles").Distinct(StringComparer.Ordinal).ToList() : _requiredClaims;
            if (needed.Count > 0) return Task.FromResult(AccessDecision.NeedsClaims(needed));
        }

        // A push that still lacks a configured claim is asked again.
        var missing = MissingClaims(request.Claims);
        if (missing.Count > 0)
        {
            return Task.FromResult(AccessDecision.NeedsClaims(missing));
        }

        // An elevated scope requires the payer role among the claims the PS
        // provided; a person without it (or without any roles) is denied rather
        // than asked again. The base scope is open to any verified agent.
        if (elevated && !HasRole(request.Claims, AdminRole))
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
        string.Equals(scope, ElevatedScope, StringComparison.Ordinal);

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
