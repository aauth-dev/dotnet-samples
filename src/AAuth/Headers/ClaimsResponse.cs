using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Headers;

/// <summary>
/// Typed reply a Person Server returns from an
/// <see cref="ClaimsRequirement"/> callback (AAuth protocol §Claims
/// Required). Carries the requested identity claims the PS holds for the
/// person. The person is already identified by the presented token, so
/// <c>sub</c> is never pushed. The SDK serializes this into the signed POST to
/// the Access Server's <c>Location</c> URL.
/// </summary>
public sealed record ClaimsResponse
{
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
        var body = new JsonObject();
        foreach (var (name, value) in Claims)
        {
            if (!AuthTokenBuilder.IsIdentityClaimAllowed(name))
                throw new System.InvalidOperationException($"Claim '{name}' is protocol-owned.");
            body[name] = value?.DeepClone();
        }
        return body;
    }
}
