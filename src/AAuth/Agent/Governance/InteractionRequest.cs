using System;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>The type of interaction relayed through the PS (§Interaction Request).</summary>
public enum InteractionType
{
    /// <summary>Relay a resource interaction requirement to the user.</summary>
    Interaction,

    /// <summary>Forward a payment approval to the user.</summary>
    Payment,

    /// <summary>Ask the user a question and receive an answer.</summary>
    Question,

    /// <summary>Propose mission completion with a summary.</summary>
    Completion,
}

/// <summary>
/// An interaction request the agent sends to the PS's <c>interaction_endpoint</c>
/// (§Interaction Request) to reach the user through the PS.
/// </summary>
/// <param name="Type">The interaction type. REQUIRED.</param>
public sealed record InteractionRequest(InteractionType Type)
{
    /// <summary>Markdown context for the user. Optional.</summary>
    public string? Description { get; init; }

    /// <summary>Interaction URL to relay (for <c>interaction</c>/<c>payment</c>). Optional.</summary>
    public string? Url { get; init; }

    /// <summary>Interaction code associated with the URL. Optional.</summary>
    public string? Code { get; init; }

    /// <summary>Markdown question for the user (for <c>question</c>). Optional.</summary>
    public string? Question { get; init; }

    /// <summary>Markdown summary of what was accomplished (for <c>completion</c>). Optional.</summary>
    public string? Summary { get; init; }

    /// <summary>
    /// Maximum seconds the PS SHOULD hold the relay's deferred response before
    /// resolving it (for <c>interaction</c>/<c>payment</c>). Optional. When the
    /// interaction URL is resource-hosted, the PS resolves once the user has
    /// engaged or this window elapses, whichever comes first (§Interaction Request).
    /// </summary>
    public int? MaxWait { get; init; }

    /// <summary>Mission binding (<c>approver</c> + <c>s256</c>). Optional.</summary>
    public MissionClaim? Mission { get; init; }

    /// <summary>The wire value for <see cref="Type"/>.</summary>
    internal string TypeValue => Type switch
    {
        InteractionType.Interaction => "interaction",
        InteractionType.Payment => "payment",
        InteractionType.Question => "question",
        InteractionType.Completion => "completion",
        _ => throw new ArgumentOutOfRangeException(nameof(Type)),
    };

    /// <summary>Render the request as the JSON request body.</summary>
    internal JsonObject ToJsonObject()
    {
        var body = new JsonObject { ["type"] = TypeValue };
        if (!string.IsNullOrEmpty(Description)) { body["description"] = Description; }
        if (!string.IsNullOrEmpty(Url)) { body["url"] = Url; }
        if (!string.IsNullOrEmpty(Code)) { body["code"] = Code; }
        if (!string.IsNullOrEmpty(Question)) { body["question"] = Question; }
        if (!string.IsNullOrEmpty(Summary)) { body["summary"] = Summary; }
        if (MaxWait is { } maxWait) { body["max_wait"] = maxWait; }
        if (Mission is not null) { body["mission"] = Mission.ToJsonObject(); }
        return body;
    }
}
