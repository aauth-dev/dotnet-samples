using System;
using System.Text.Json.Nodes;

namespace AAuth.Tokens;

/// <summary>
/// PS-side helper to construct the nested <c>act</c> claim for downstream
/// auth tokens per §Upstream Token Verification step 4.
/// </summary>
public static class ActChainBuilder
{
    /// <summary>
    /// Construct the nested act claim for a downstream auth token.
    /// Wraps the upstream token's act inside a new act identifying the intermediary.
    /// </summary>
    /// <remarks>
    /// This is a standalone utility for manual act chain construction.
    /// Do NOT pass the result to <see cref="AuthTokenBuilder.UpstreamAct"/> — the builder
    /// performs its own nesting. Pass the raw upstream act to the builder instead.
    /// </remarks>
    /// <param name="intermediaryAgentId">The intermediary resource's agent identifier.</param>
    /// <param name="upstreamAct">The act claim from the validated upstream token.</param>
    /// <returns>A new JsonObject representing the full nested act chain.</returns>
    /// <example>
    /// Input: intermediaryAgentId = "aauth:orch@example", upstreamAct = { "sub": "aauth:agent@example" }
    /// Output: { "sub": "aauth:orch@example", "act": { "sub": "aauth:agent@example" } }
    /// </example>
    public static JsonObject BuildNestedAct(string intermediaryAgentId, JsonObject upstreamAct)
    {
        ArgumentException.ThrowIfNullOrEmpty(intermediaryAgentId);
        ArgumentNullException.ThrowIfNull(upstreamAct);

        return new JsonObject
        {
            ["sub"] = intermediaryAgentId,
            ["act"] = upstreamAct.DeepClone(),
        };
    }

    /// <summary>
    /// Validate that a constructed act chain is semantically consistent:
    /// each level has a <c>sub</c> and nested levels don't exceed max depth.
    /// </summary>
    /// <param name="act">The act claim to validate.</param>
    /// <param name="maxDepth">Maximum allowed nesting depth (default 10).</param>
    /// <returns><c>true</c> if valid; <c>false</c> if missing sub or too deep.</returns>
    public static bool ValidateChain(JsonObject act, int maxDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(act);

        var current = act;
        int depth = 0;

        while (current is not null)
        {
            if (++depth > maxDepth)
                return false;

            if (string.IsNullOrEmpty((string?)current["sub"]))
                return false;

            current = current["act"] as JsonObject;
        }

        return true;
    }
}
