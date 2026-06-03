using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// Pluggable Access Server authorization-policy seam. An implementation is the
/// Policy Decision Point for the AS token endpoint: given the verified request
/// context it returns an <see cref="AccessDecision"/> the
/// <c>MapAAuthAccessServer</c> host helper turns into the spec-mandated wire
/// response (mint, <c>403 access_denied</c>, <c>202 requirement=claims</c>,
/// <c>202 requirement=interaction</c>, or <c>402 Payment Required</c>). AAuth
/// crypto stays in the host; the policy only decides.
/// </summary>
public interface IAccessPolicy
{
    /// <summary>Evaluate the access request and return a decision.</summary>
    Task<AccessDecision> EvaluateAsync(
        AccessPolicyRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Optional extension of <see cref="IAccessPolicy"/> for policies whose
/// decision requires an interactive user login/consent (e.g. an OIDC
/// authorization-code round-trip). The host surfaces
/// <see cref="AccessDecisionKind.NeedsInteraction"/> as
/// <c>202 requirement=interaction</c>; the AS's interaction endpoints call
/// <see cref="BuildAuthorizationUrl"/> to start the flow and
/// <see cref="CompleteAsync"/> to resolve the verdict on the callback.
/// </summary>
public interface IInteractiveAccessPolicy
{
    /// <summary>Build the identity-provider authorization URL for the interaction.</summary>
    string BuildAuthorizationUrl(string state, string redirectUri);

    /// <summary>Complete the interaction (exchange the code, fetch the verdict).</summary>
    Task<AccessDecision> CompleteAsync(
        string code, string redirectUri, AccessPolicyRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>The verified context an <see cref="IAccessPolicy"/> decides on.</summary>
public sealed class AccessPolicyRequest
{
    /// <summary>The resource URL the auth token will be audienced to (<c>aud</c>).</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope (from the resource token).</summary>
    public required string Scope { get; init; }

    /// <summary>The verified agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// Identity claims known so far (e.g. derived from the agent or pushed by
    /// the Person Server via §Claims Required). <see langword="null"/> when none.
    /// </summary>
    public JsonObject? Claims { get; init; }

    /// <summary>The pending-entry id when the request resumes an interaction.</summary>
    public string? InteractionId { get; init; }
}

/// <summary>The kinds of decision an <see cref="IAccessPolicy"/> can return.</summary>
public enum AccessDecisionKind
{
    /// <summary>Grant access — mint the auth token.</summary>
    Allow,

    /// <summary>Deny access — <c>403 access_denied</c>.</summary>
    Deny,

    /// <summary>An interactive user login/consent is required (§Trust Establishment).</summary>
    NeedsInteraction,

    /// <summary>Identity claims are required before deciding (§Claims Required).</summary>
    NeedsClaims,

    /// <summary>Payment is required (§Payment Required → <c>402</c>).</summary>
    NeedsPayment,
}

/// <summary>
/// The outcome of an <see cref="IAccessPolicy"/> evaluation. Use the static
/// factory methods rather than the constructor so each decision kind carries
/// only the fields that apply to it.
/// </summary>
public sealed class AccessDecision
{
    private AccessDecision(
        AccessDecisionKind kind,
        string? reason = null,
        string? interactionUrl = null,
        IReadOnlyList<string>? requiredClaims = null,
        string? paymentUrl = null,
        string? subject = null,
        string? tenant = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
    {
        Kind = kind;
        Reason = reason;
        InteractionUrl = interactionUrl;
        RequiredClaims = requiredClaims;
        PaymentUrl = paymentUrl;
        Subject = subject;
        Tenant = tenant;
        AdditionalClaims = additionalClaims;
    }

    /// <summary>The decision kind.</summary>
    public AccessDecisionKind Kind { get; }

    /// <summary>Human-readable denial reason (<see cref="AccessDecisionKind.Deny"/>).</summary>
    public string? Reason { get; }

    /// <summary>
    /// Optional identity-provider interaction URL
    /// (<see cref="AccessDecisionKind.NeedsInteraction"/>). The host may
    /// instead advertise its own hosted login endpoint.
    /// </summary>
    public string? InteractionUrl { get; }

    /// <summary>
    /// The claim names the recipient must push
    /// (<see cref="AccessDecisionKind.NeedsClaims"/>, §Claims Required).
    /// </summary>
    public IReadOnlyList<string>? RequiredClaims { get; }

    /// <summary>
    /// The payment URL advertised in the <c>Location</c> header
    /// (<see cref="AccessDecisionKind.NeedsPayment"/>, §Payment Required).
    /// </summary>
    public string? PaymentUrl { get; }

    /// <summary>
    /// Optional directed (pairwise) user identifier the policy asserts on an
    /// <see cref="AccessDecisionKind.Allow"/>. When the principal's identity
    /// arrives via a §Claims Required push instead, the host uses the pushed
    /// <c>sub</c>.
    /// </summary>
    public string? Subject { get; }

    /// <summary>Optional <c>tenant</c> claim asserted on an allow.</summary>
    public string? Tenant { get; }

    /// <summary>Optional extra identity claims asserted on an allow.</summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; }

    /// <summary>Grant access. Optionally assert a directed identity on the token.</summary>
    public static AccessDecision Allow(
        string? subject = null,
        string? tenant = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
        => new(AccessDecisionKind.Allow, subject: subject, tenant: tenant, additionalClaims: additionalClaims);

    /// <summary>Deny access with a reason.</summary>
    public static AccessDecision Deny(string reason)
        => new(AccessDecisionKind.Deny, reason: reason);

    /// <summary>Require an interactive user login/consent.</summary>
    public static AccessDecision NeedsInteraction(string? interactionUrl = null)
        => new(AccessDecisionKind.NeedsInteraction, interactionUrl: interactionUrl);

    /// <summary>Require the recipient to push the named identity claims.</summary>
    public static AccessDecision NeedsClaims(IReadOnlyList<string> requiredClaims)
        => new(AccessDecisionKind.NeedsClaims, requiredClaims: requiredClaims);

    /// <summary>Require payment, advertising a payment URL in the <c>Location</c> header.</summary>
    public static AccessDecision NeedsPayment(string paymentUrl)
        => new(AccessDecisionKind.NeedsPayment, paymentUrl: paymentUrl);
}
