using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace AAuth.Headers;

/// <summary>
/// Typed reply a Person Server returns from an
/// <see cref="AAuthClaimsRequirement"/> callback (AAuth protocol §Claims
/// Required). Carries the directed user identifier (<see cref="Subject"/>) the
/// recipient MUST supply as <c>sub</c>, plus any of the requested identity
/// claims the PS holds for the bound principal. The SDK serializes this into
/// the signed POST to the Access Server's <c>Location</c> URL.
/// </summary>
public sealed record AAuthClaimsResponse
{
    /// <summary>
    /// The directed (pairwise) user identifier for the requesting resource —
    /// pushed as the <c>sub</c> field. REQUIRED by §Claims Required.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The released identity claims, keyed by claim name (e.g. <c>email</c>,
    /// <c>tenant</c>). Claims the PS does not hold are simply omitted; the
    /// recipient ignores claims it did not request.
    /// </summary>
    public IReadOnlyDictionary<string, JsonNode?> Claims { get; init; }
        = new Dictionary<string, JsonNode?>();

    /// <summary>Serialize to the JSON body pushed to the AS Location URL.</summary>
    public JsonObject ToJson()
    {
        var body = new JsonObject { ["sub"] = Subject };
        foreach (var (name, value) in Claims)
        {
            if (name == "sub")
            {
                continue;
            }
            body[name] = value?.DeepClone();
        }
        return body;
    }
}
