using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace AAuth.Headers;

/// <summary>
/// Typed projection of an <c>AAuth-Requirement: requirement=clarification</c>
/// response (AAuth protocol §Clarification Required). Carries the question the
/// server needs answered before it can proceed, plus optional timeout and
/// discrete-choice metadata. See
/// <see href="https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/">draft-hardt-oauth-aauth-protocol §Clarification Chat</see>.
/// </summary>
/// <remarks>
/// Per the spec the question is carried in the response body's
/// <c>clarification</c> field (a Markdown string), with optional
/// <c>timeout</c> (seconds) and <c>options</c> (discrete string choices)
/// fields. The <c>AAuth-Requirement</c> header carries only the requirement
/// type. The <c>clarification</c> value is untrusted input and MUST be
/// sanitized before display to a user.
/// </remarks>
/// <param name="Clarification">The Markdown question posed to the recipient.</param>
/// <param name="TimeoutSeconds">Optional deadline (seconds) to respond by.</param>
/// <param name="Options">Optional discrete choices when the question is closed.</param>
public sealed record ClarificationRequirement(
    string Clarification,
    int? TimeoutSeconds = null,
    IReadOnlyList<string>? Options = null)
{
    /// <summary>Requirement type: <c>clarification</c>.</summary>
    public const string RequirementType = "clarification";

    /// <summary>The response-body field carrying the question.</summary>
    public const string ClarificationField = "clarification";

    /// <summary>The response-body field carrying the optional timeout (seconds).</summary>
    public const string TimeoutField = "timeout";

    /// <summary>The response-body field carrying the optional discrete choices.</summary>
    public const string OptionsField = "options";

    /// <summary>
    /// Project a <c>clarification</c> requirement from a parsed
    /// <c>AAuth-Requirement</c> header and the (already-read) JSON response
    /// body. Returns <see langword="null"/> when the requirement is something
    /// else. Throws <see cref="FormatException"/> when the requirement is
    /// <c>clarification</c> but the body does not carry a non-empty
    /// <c>clarification</c> string (§Clarification Required).
    /// </summary>
    public static ClarificationRequirement? FromResponse(
        AAuthRequirementHeader.ParsedRequirement requirement,
        JsonObject? body)
    {
        ArgumentNullException.ThrowIfNull(requirement);
        if (requirement.Requirement != RequirementType)
        {
            return null;
        }

        var question = (string?)body?[ClarificationField];
        if (string.IsNullOrWhiteSpace(question))
        {
            throw new FormatException(
                $"AAuth-Requirement requirement=clarification did not carry a question "
                + $"(expected a '{ClarificationField}' string in the response body).");
        }

        int? timeout = null;
        if (body?[TimeoutField] is JsonValue timeoutValue
            && timeoutValue.TryGetValue(out int seconds))
        {
            timeout = seconds;
        }

        IReadOnlyList<string>? options = null;
        if (body?[OptionsField] is JsonArray array)
        {
            var values = new List<string>();
            foreach (var node in array)
            {
                var value = (string?)node;
                if (!string.IsNullOrWhiteSpace(value))
                {
                    values.Add(value);
                }
            }
            if (values.Count > 0)
            {
                options = values.ToArray();
            }
        }

        return new ClarificationRequirement(question, timeout, options);
    }
}
