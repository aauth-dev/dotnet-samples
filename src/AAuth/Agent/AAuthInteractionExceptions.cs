using System;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Thrown when a deferred AAuth interaction terminates with explicit
/// user denial. Surfaced when the PS responds to a pending-URL poll
/// with <c>403</c> and a body containing <c>error: "denied"</c>.
/// </summary>
/// <remarks>
/// Distinct from a generic <see cref="System.Net.Http.HttpRequestException"/>
/// so callers (UIs, retry policies, tests) can react to denial without
/// having to inspect status codes. A bare <c>404</c> on the pending URL
/// is treated as "unknown / expired" — a different failure mode and
/// still surfaces as <see cref="System.Net.Http.HttpRequestException"/>.
/// </remarks>
public sealed class AAuthInteractionDeniedException : Exception
{
    public AAuthInteractionDeniedException(string message)
        : base(message) { }

    public AAuthInteractionDeniedException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when a deferred AAuth interaction exhausts its polling budget
/// without ever resolving to a terminal response — the user neither
/// approved nor denied within the time window.
/// </summary>
/// <remarks>
/// Wraps the underlying <see cref="TimeoutException"/> from
/// <see cref="DeferredPoller"/> so callers can distinguish "user walked
/// away" from "user explicitly denied" (<see cref="AAuthInteractionDeniedException"/>)
/// and from transport errors.
/// </remarks>
public sealed class AAuthInteractionTimeoutException : Exception
{
    public AAuthInteractionTimeoutException(string message)
        : base(message) { }

    public AAuthInteractionTimeoutException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown by an intermediary's <c>OnInteractionRequired</c> callback to abort an
/// in-flight token exchange <em>before</em> it blocks polling the deferred
/// <c>Location</c>, so the intermediary can re-emit its own
/// <c>202 requirement=interaction</c> to its caller (AAuth protocol
/// §Interaction Chaining).
/// </summary>
/// <remarks>
/// <para>A resource acting as an agent (e.g. an orchestrator) has no user to
/// relay an interaction to. When its downstream token exchange returns
/// <c>202 requirement=interaction</c>, the SDK invokes the configured
/// <c>OnInteractionRequired</c> callback and would then <em>blocking-poll</em>
/// the deferred <c>Location</c> until the user acts. An intermediary instead
/// throws this exception from the callback: because the exchange wraps the
/// callback in <c>try/finally</c> with no <c>catch</c>, the throw unwinds the
/// exchange cleanly (response disposed, no double-write, no blocking poll) and
/// propagates out of the originating <c>GetAsync</c>.</para>
/// <para>The intermediary's request handler catches it, persists pending state
/// keyed by its own id, and re-emits its own <c>202</c> carrying the captured
/// <see cref="Interaction"/> (the downstream PS <c>url</c> and <c>code</c>,
/// passed through) plus the intermediary's own <c>Location</c>.</para>
/// </remarks>
public sealed class AAuthInteractionChainedException : Exception
{
    /// <summary>
    /// The interaction requirement captured from the downstream <c>202</c> —
    /// the user-facing <c>url</c> and single-use <c>code</c> the intermediary
    /// passes through when re-emitting its own requirement.
    /// </summary>
    public Interaction Interaction { get; }

    public AAuthInteractionChainedException(Interaction interaction)
        : base("Downstream exchange requires user interaction; re-emitting as a chained interaction requirement.")
    {
        ArgumentNullException.ThrowIfNull(interaction);
        Interaction = interaction;
    }

    public AAuthInteractionChainedException(Interaction interaction, string message)
        : base(message)
    {
        ArgumentNullException.ThrowIfNull(interaction);
        Interaction = interaction;
    }
}

/// <summary>
/// Thrown when the agent cancels an in-flight token exchange in response to a
/// clarification by DELETE-ing the pending URL (AAuth protocol §Cancel
/// Request). The PS terminates the consent session; subsequent requests to the
/// pending URL return <c>410 Gone</c>.
/// </summary>
public sealed class AAuthClarificationCancelledException : Exception
{
    public AAuthClarificationCancelledException(string message)
        : base(message) { }
}

/// <summary>
/// Thrown when a clarification chat exceeds the configured maximum number of
/// rounds (AAuth protocol §Clarification Limits, recommended 5). Guards the
/// agent against an unbounded back-and-forth with the PS.
/// </summary>
public sealed class AAuthClarificationLimitException : Exception
{
    /// <summary>The round limit that was exceeded.</summary>
    public int MaxRounds { get; }

    public AAuthClarificationLimitException(int maxRounds)
        : base($"Clarification chat exceeded the maximum of {maxRounds} round(s).")
    {
        MaxRounds = maxRounds;
    }
}
