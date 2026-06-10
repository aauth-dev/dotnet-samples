using System.Text.Json.Nodes;

namespace AAuth.Agent.Governance;

/// <summary>
/// The terminal result of an interaction request (§Interaction Response). The
/// populated fields depend on the request <see cref="InteractionType"/>:
/// <list type="bullet">
/// <item><c>question</c> populates <see cref="Answer"/>.</item>
/// <item><c>completion</c> populates <see cref="Terminated"/>.</item>
/// <item><c>interaction</c>/<c>payment</c> resolve once the user completes.</item>
/// </list>
/// </summary>
/// <param name="Type">The interaction type this result is for.</param>
public sealed record InteractionResult(InteractionType Type)
{
    /// <summary>The user's answer (for <c>question</c>).</summary>
    public string? Answer { get; init; }

    /// <summary>
    /// Whether the mission was terminated (for <c>completion</c> — the user
    /// accepted the summary). <see langword="false"/> means the mission remains
    /// active (the user had follow-ups).
    /// </summary>
    public bool Terminated { get; init; }

    /// <summary>The raw terminal response body, if any.</summary>
    public JsonObject? Body { get; init; }

    /// <summary>
    /// The deferred-response <c>status</c> when present (e.g. <c>"interacting"</c>
    /// once the user has engaged with a resource-hosted interaction). Agents treat
    /// unrecognized values as <c>"pending"</c> (§Deferred Responses).
    /// </summary>
    public string? Status { get; init; }

    /// <summary>
    /// <see langword="true"/> when the PS returned <c>424 interaction_unavailable</c>
    /// (§Interaction Endpoint Errors): it has no channel to relay this specific
    /// interaction/payment. Non-terminal — the agent falls back to directing the
    /// user itself. Distinct from the terminal <c>user_unreachable</c>.
    /// </summary>
    public bool Unavailable { get; init; }
}
