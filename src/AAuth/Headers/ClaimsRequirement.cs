using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace AAuth.Headers;

/// <summary>
/// Typed projection of an <c>AAuth-Requirement: requirement=claims</c>
/// response (AAuth protocol §Claims Required). Carries the list of claim
/// names the server needs to process the request. The recipient (a Person
/// Server) MUST supply these claims — including a directed user identifier as
/// <c>sub</c> — by POSTing a signed request to the response's
/// <c>Location</c> URL. See
/// <see href="https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/">draft-hardt-oauth-aauth-protocol §Claims Required</see>.
/// </summary>
/// <remarks>
/// <para>Per the spec the requested claim names are carried in the response
/// body's <c>required_claims</c> field. The <c>AAuth-Requirement</c> header
/// carries no claim names.</para>
/// </remarks>
public sealed record ClaimsRequirement(IReadOnlyList<string> RequiredClaims)
{
    /// <summary>Requirement type: <c>claims</c>.</summary>
    public const string RequirementType = "claims";

    /// <summary>The response-body field carrying the requested claim names.</summary>
    public const string RequiredClaimsField = "required_claims";

    /// <summary>
    /// Project a <c>claims</c> requirement from a parsed
    /// <c>AAuth-Requirement</c> header and the (already-read) JSON response
    /// body. Returns <see langword="null"/> when the requirement is something
    /// else. The requested claim names are read from the body's
    /// <c>required_claims</c> array (§Claims Required). Throws
    /// <see cref="FormatException"/> when the requirement is <c>claims</c> but
    /// the body does not carry a non-empty <c>required_claims</c> array.
    /// </summary>
    public static ClaimsRequirement? FromResponse(
        AAuthRequirementHeader.ParsedRequirement requirement,
        JsonObject? body)
    {
        ArgumentNullException.ThrowIfNull(requirement);
        if (requirement.Requirement != RequirementType)
        {
            return null;
        }

        var names = new List<string>();

        if (body?[RequiredClaimsField] is JsonArray array)
        {
            foreach (var node in array)
            {
                var name = (string?)node;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    names.Add(name);
                }
            }
        }

        if (names.Count == 0)
        {
            throw new FormatException(
                $"AAuth-Requirement requirement=claims did not carry any claim names "
                + $"(expected a '{RequiredClaimsField}' array in the response body).");
        }

        return new ClaimsRequirement(names.Distinct(StringComparer.Ordinal).ToArray());
    }
}
