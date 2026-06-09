using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Tokens;

namespace AAuth.Person;

/// <summary>
/// Pluggable Person Server identity/consent seam — the PS counterpart to
/// <c>AAuth.Access.IAccessPolicy</c>. Given the verified token-request context
/// it returns an <see cref="IdentityAssertion"/> the
/// <c>MapAAuthPersonServer</c> host helper turns into the spec-mandated wire
/// response: mint the auth token (asserting a directed <c>sub</c> + identity
/// claims and confirming consent), <c>403 denied</c>, or
/// <c>202 requirement=interaction</c> while the user reviews. AAuth crypto
/// (resource-token verification, the auth-token mint, the §Auth Token Delivery
/// check, AS federation) stays in the host; the asserter only decides.
/// </summary>
/// <remarks>
/// In a three-party (PS-asserted) exchange the asserter supplies the identity
/// and consent decision directly. In a four-party (federated) exchange the
/// same asserter answers the AS's §Claims Required push: the host maps an
/// <see cref="IdentityAssertion.Assert"/> into the directed <c>sub</c> + claims
/// pushed to the AS. The host packages the mission three-gate model around the
/// asserter (terminated rejection and prior-consent silent grant use the
/// <c>IMissionStore</c>/<c>IMissionLog</c> primitives); the asserter owns the
/// in-scope / prompt policy decision for a mission-bound request.
/// </remarks>
public interface IIdentityClaimsAsserter
{
    /// <summary>Decide identity + consent for the request and return an assertion.</summary>
    Task<IdentityAssertion> AssertAsync(
        IdentityAssertionRequest request, CancellationToken cancellationToken = default);
}

/// <summary>The verified context an <see cref="IIdentityClaimsAsserter"/> decides on.</summary>
public sealed class IdentityAssertionRequest
{
    /// <summary>The resource URL the auth token will be audienced to (the resource token's <c>iss</c>).</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope (from the resource token).</summary>
    public required string Scope { get; init; }

    /// <summary>The verified agent identifier (the agent token's <c>sub</c>).</summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// The claim names the recipient asked for. In a four-party exchange these
    /// are the AS's §Claims Required names; in a three-party exchange this is
    /// <see langword="null"/> (the resource applies its own policy on whatever
    /// the PS asserts).
    /// </summary>
    public IReadOnlyList<string>? RequiredClaims { get; init; }

    /// <summary>
    /// The mission context (if any) the resource token carried. When set, the
    /// request is governed by the mission; the asserter decides whether the
    /// (resource, scope) is within the mission's approved intent (silent
    /// <see cref="IdentityAssertion.Assert"/>) or needs the user
    /// (<see cref="IdentityAssertion.NeedsConsent"/>).
    /// </summary>
    public MissionClaim? Mission { get; init; }

    /// <summary>
    /// The OIDC <c>prompt</c> value from the token request, if any (space-delimited
    /// <c>none</c>/<c>login</c>/<c>consent</c>/<c>select_account</c>, §Agent Token
    /// Request). The asserter MAY honor it (e.g. force a consent prompt). Unknown
    /// values are tolerated and ignored.
    /// </summary>
    public string? Prompt { get; init; }

    /// <summary>
    /// The capabilities the agent declared in the token request body, if any
    /// (§Agent Token Request — the request-body equivalent of the
    /// <c>AAuth-Capabilities</c> header). Without a mission this is how the PS
    /// learns what the agent can drive (e.g. <c>interaction</c>); within a mission
    /// these refresh the values captured at approval. Unknown values are tolerated.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>The pending-entry id when the request resumes a parked consent.</summary>
    public string? InteractionId { get; init; }
}

/// <summary>The kinds of decision an <see cref="IIdentityClaimsAsserter"/> can return.</summary>
public enum IdentityAssertionKind
{
    /// <summary>Assert identity + consent — mint the auth token (or push the claims).</summary>
    Assert,

    /// <summary>Deny the request — <c>403 denied</c>.</summary>
    Deny,

    /// <summary>The user must review/consent first (§Interaction → <c>202</c>).</summary>
    NeedsConsent,
}

/// <summary>
/// The outcome of an <see cref="IIdentityClaimsAsserter"/> evaluation. Use the
/// static factory methods rather than the constructor so each decision kind
/// carries only the fields that apply to it.
/// </summary>
public sealed class IdentityAssertion
{
    private IdentityAssertion(
        IdentityAssertionKind kind,
        string? subject = null,
        string? tenant = null,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null,
        string? reason = null)
    {
        Kind = kind;
        Subject = subject;
        Tenant = tenant;
        Roles = roles;
        Groups = groups;
        AdditionalClaims = additionalClaims;
        Reason = reason;
    }

    /// <summary>The decision kind.</summary>
    public IdentityAssertionKind Kind { get; }

    /// <summary>The directed (pairwise) user identifier — the auth token's <c>sub</c>.</summary>
    public string? Subject { get; }

    /// <summary>The asserted tenant claim, if any.</summary>
    public string? Tenant { get; }

    /// <summary>The asserted role claims, if any.</summary>
    public IReadOnlyList<string>? Roles { get; }

    /// <summary>The asserted group claims, if any.</summary>
    public IReadOnlyList<string>? Groups { get; }

    /// <summary>Any further asserted identity claims (e.g. <c>email</c>), if any.</summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; }

    /// <summary>Human-readable denial reason (<see cref="IdentityAssertionKind.Deny"/>).</summary>
    public string? Reason { get; }

    /// <summary>
    /// Assert identity + consent. <paramref name="subject"/> is the directed
    /// <c>sub</c>; the remaining fields are optional asserted identity claims.
    /// </summary>
    public static IdentityAssertion Assert(
        string subject,
        string? tenant = null,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? groups = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null)
        => new(IdentityAssertionKind.Assert, subject, tenant, roles, groups, additionalClaims);

    /// <summary>Deny the request with a reason.</summary>
    public static IdentityAssertion Deny(string reason)
        => new(IdentityAssertionKind.Deny, reason: reason);

    /// <summary>Require the user to review/consent before the request resolves.</summary>
    public static IdentityAssertion NeedsConsent()
        => new(IdentityAssertionKind.NeedsConsent);
}

/// <summary>
/// The default <see cref="IIdentityClaimsAsserter"/>: asserts a fixed directed
/// <c>sub</c> and no further claims, with no consent prompt. Suitable for a
/// non-interactive demo PS; a production PS swaps in an implementation that
/// derives the principal's directed identity and consent decision.
/// </summary>
public sealed class DefaultIdentityClaimsAsserter : IIdentityClaimsAsserter
{
    private readonly string _subject;

    /// <summary>Create the default asserter.</summary>
    /// <param name="subject">The directed <c>sub</c> to assert. Default <c>pairwise-sub</c>.</param>
    public DefaultIdentityClaimsAsserter(string subject = "pairwise-sub")
    {
        _subject = subject;
    }

    /// <inheritdoc />
    public Task<IdentityAssertion> AssertAsync(
        IdentityAssertionRequest request, CancellationToken cancellationToken = default)
        => Task.FromResult(IdentityAssertion.Assert(_subject));
}
