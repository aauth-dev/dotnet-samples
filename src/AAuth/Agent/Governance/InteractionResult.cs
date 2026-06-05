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
}
