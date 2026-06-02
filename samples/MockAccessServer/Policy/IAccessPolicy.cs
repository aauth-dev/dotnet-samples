using System.Text.Json.Nodes;

namespace MockAccessServer.Policy;

/// <summary>
/// The Access Server's pluggable Policy Decision Point. The AAuth crypto
/// (verifying the PS signature, the agent token, and the resource token, then
/// minting the <c>aa-auth+jwt</c>) stays in the adapter; only the
/// allow/deny/needs-interaction <em>decision</em> is delegated here.
///
/// Two providers ship:
/// <list type="bullet">
///   <item><c>StubAccessPolicy</c> — a pure-.NET stand-in encoding the demo
///   policy locally (no Docker); the default so <c>make e2e</c>/CI stay
///   dependency-free.</item>
///   <item><c>KeycloakAccessPolicy</c> — delegates to Keycloak's
///   Authorization Services (interactive login/consent + <c>uma-ticket</c>
///   decision).</item>
/// </list>
/// </summary>
public interface IAccessPolicy
{
    /// <summary>
    /// Decide whether the verified agent may obtain an auth token for the
    /// requested resource + scope.
    /// </summary>
    Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Optional capability for policies that resolve the decision through an
/// interactive user round-trip (browser login + consent). The AS hosts the
/// <c>/interaction/login</c> redirect and <c>/interaction/callback</c>
/// endpoints and drives them through this contract; non-interactive policies
/// (e.g. <c>StubAccessPolicy</c>) do not implement it.
/// </summary>
public interface IInteractiveAccessPolicy
{
    /// <summary>
    /// Build the identity-provider authorization URL the user's browser is
    /// redirected to. <paramref name="state"/> is the AS pending-interaction id
    /// (echoed back on the callback); <paramref name="redirectUri"/> is the
    /// AS callback endpoint.
    /// </summary>
    string BuildAuthorizationUrl(string state, string redirectUri);

    /// <summary>
    /// Complete the round-trip: exchange the authorization <paramref name="code"/>
    /// for the user's token and evaluate the policy decision for
    /// <paramref name="request"/>. Returns <see cref="AccessDecisionKind.Allow"/>
    /// or <see cref="AccessDecisionKind.Deny"/> (never NeedsInteraction).
    /// </summary>
    Task<AccessDecision> CompleteAsync(
        string code, string redirectUri, AccessPolicyRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Inputs to a policy decision, derived from the verified tokens.</summary>
public sealed class AccessPolicyRequest
{
    /// <summary>The resource (the resource token's <c>iss</c>; the auth token's <c>aud</c>).</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope (from the verified resource token).</summary>
    public required string Scope { get; init; }

    /// <summary>The verified agent id (the agent token's <c>sub</c>).</summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// Person-Server-asserted claims about the principal (e.g. <c>roles</c>,
    /// <c>groups</c>) available to ABAC policies. Pushed to Keycloak via the
    /// <c>claim_token</c>.
    /// </summary>
    public JsonObject? Claims { get; init; }

    /// <summary>
    /// An opaque correlation handle the AS uses to resume a decision after an
    /// interactive login/consent round-trip (the pending-poll id). Null on the
    /// first evaluation.
    /// </summary>
    public string? InteractionId { get; init; }
}

/// <summary>The outcome of a policy decision.</summary>
public enum AccessDecisionKind
{
    /// <summary>Mint the auth token.</summary>
    Allow,

    /// <summary>Refuse — terminal <c>403 access_denied</c>.</summary>
    Deny,

    /// <summary>A human decision is required — emit <c>202 requirement=interaction</c>.</summary>
    NeedsInteraction,
}

/// <summary>A policy verdict: allow, deny, or needs-interaction.</summary>
public sealed class AccessDecision
{
    private AccessDecision(AccessDecisionKind kind, string? reason, string? interactionUrl)
    {
        Kind = kind;
        Reason = reason;
        InteractionUrl = interactionUrl;
    }

    public AccessDecisionKind Kind { get; }

    /// <summary>Human-readable reason (used in the <c>403</c> body on deny).</summary>
    public string? Reason { get; }

    /// <summary>Where the user must go to authenticate/consent (on needs-interaction).</summary>
    public string? InteractionUrl { get; }

    public static AccessDecision Allow() => new(AccessDecisionKind.Allow, null, null);

    public static AccessDecision Deny(string reason) => new(AccessDecisionKind.Deny, reason, null);

    public static AccessDecision NeedsInteraction(string interactionUrl) =>
        new(AccessDecisionKind.NeedsInteraction, null, interactionUrl);
}
