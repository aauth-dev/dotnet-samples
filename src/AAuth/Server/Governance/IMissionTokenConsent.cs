using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Tokens;

namespace AAuth.Server.Governance;

/// <summary>
/// Which step of the out-of-scope mission token gate (§Agent Token Request, gate
/// 2c) the consumer is being asked to decide.
/// </summary>
public enum MissionTokenConsentStage
{
    /// <summary>
    /// The initial evaluation at the token endpoint. A <see cref="MissionTokenConsentKind.Grant"/>
    /// here is the silent in-scope grant (gate 2a); any other outcome defers the
    /// request to an interactive review (gate 2c).
    /// </summary>
    Gate,

    /// <summary>
    /// A later evaluation while the agent polls the pending URL — after the user
    /// channel has been engaged, or after the agent answered a clarification.
    /// </summary>
    Resolve,
}

/// <summary>The action the PS takes for an out-of-scope mission token request.</summary>
public enum MissionTokenConsentKind
{
    /// <summary>Issue the auth token. Identity claims come from <see cref="AAuth.Person.IIdentityClaimsAsserter"/>.</summary>
    Grant,

    /// <summary>Refuse the request (<c>403 denied</c>).</summary>
    Deny,

    /// <summary>
    /// Ask the agent a question before deciding (§Clarification Chat). The SDK
    /// emits <c>requirement=clarification</c> and resumes the review once the
    /// agent answers.
    /// </summary>
    Clarify,

    /// <summary>
    /// Engage the user channel and hold the request (§User Interaction). The SDK
    /// returns a deferred <c>202</c> and the agent polls until the decision lands
    /// (via a later <see cref="Grant"/>/<see cref="Deny"/>, or an out-of-band
    /// <c>MarkAllowed</c>/<c>MarkDenied</c> on the pending store).
    /// </summary>
    Interact,
}

/// <summary>
/// The PS's decision for an out-of-scope mission token request. Built with the
/// <see cref="Grant"/>/<see cref="Deny"/>/<see cref="Clarify"/>/<see cref="Interact"/>
/// factories.
/// </summary>
public sealed record MissionTokenConsentDecision
{
    /// <summary>The action to take.</summary>
    public MissionTokenConsentKind Kind { get; private init; }

    /// <summary>An optional human-readable reason (surfaced on <see cref="MissionTokenConsentKind.Deny"/>).</summary>
    public string? Reason { get; private init; }

    /// <summary>The clarification question (for <see cref="MissionTokenConsentKind.Clarify"/>).</summary>
    public string? Question { get; private init; }

    /// <summary>Optional seconds until the clarification times out (#requirement-clarification).</summary>
    public int? Timeout { get; private init; }

    /// <summary>Optional discrete choices for the clarification (#requirement-clarification).</summary>
    public IReadOnlyList<string>? Options { get; private init; }

    /// <summary>Issue the auth token.</summary>
    public static MissionTokenConsentDecision Grant() => new() { Kind = MissionTokenConsentKind.Grant };

    /// <summary>Refuse the request, optionally with a reason.</summary>
    public static MissionTokenConsentDecision Deny(string? reason = null)
        => new() { Kind = MissionTokenConsentKind.Deny, Reason = reason };

    /// <summary>Ask the agent <paramref name="question"/> before deciding.</summary>
    public static MissionTokenConsentDecision Clarify(
        string question, int? timeout = null, IReadOnlyList<string>? options = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(question);
        return new() { Kind = MissionTokenConsentKind.Clarify, Question = question, Timeout = timeout, Options = options };
    }

    /// <summary>Engage the user channel and hold the request for a deferred decision.</summary>
    public static MissionTokenConsentDecision Interact() => new() { Kind = MissionTokenConsentKind.Interact };
}

/// <summary>
/// The input to an <see cref="IMissionTokenConsent"/> review.
/// </summary>
public sealed record MissionTokenConsentContext
{
    /// <summary>The verified agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>The resource URL the auth token would be audienced to (the resource token's <c>iss</c>).</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The mission governing the request.</summary>
    public required MissionClaim Mission { get; init; }

    /// <summary>Which step of the gate this review is.</summary>
    public MissionTokenConsentStage Stage { get; init; }

    /// <summary>The agent's optional natural-language justification (#aauth-prompt).</summary>
    public string? Prompt { get; init; }

    /// <summary>The agent's declared capabilities (#aauth-capabilities), e.g. <c>clarification</c>.</summary>
    public IReadOnlyList<string>? Capabilities { get; init; }

    /// <summary>
    /// The clarification answers the agent has supplied so far, oldest first
    /// (§Clarification Chat). Empty until the agent answers a <see cref="MissionTokenConsentKind.Clarify"/>.
    /// </summary>
    public IReadOnlyList<string> ClarificationHistory { get; init; } = Array.Empty<string>();
}

/// <summary>
/// The PS-side decision seam for an out-of-scope mission token request
/// (§Agent Token Request, gate 2c). The SDK owns the protocol — the
/// <c>requirement=clarification</c> round-trip, the deferred <c>202</c>/poll, and
/// the mission-log entries — and calls this seam for the <em>decision</em>. A PS
/// supplies the policy (a scripted test, a human consent screen, or an LLM-driven
/// reviewer that generates clarification questions and evaluates the answers).
/// Spec basis: AAuth "does not prescribe how the decision is made."
/// </summary>
public interface IMissionTokenConsent
{
    /// <summary>Decide what to do with <paramref name="context"/>.</summary>
    Task<MissionTokenConsentDecision> ReviewAsync(
        MissionTokenConsentContext context, CancellationToken cancellationToken = default);
}
