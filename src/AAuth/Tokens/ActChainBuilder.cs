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
    /// Construct the nested <c>act</c> node for a downstream auth token
    /// (§Delegation Chain). The node identifies the <em>immediate upstream</em>
    /// agent (the delegator) via <c>act.agent</c>; the upstream agent's own chain,
    /// if any, is nested as <c>act.act</c>. The presenter's identity stays in the
    /// token's top-level <c>agent</c> claim and is not repeated here.
    /// </summary>
    /// <param name="upstreamAgentId">The immediate upstream agent identifier (delegator).</param>
    /// <param name="upstreamChain">The upstream agent's own <c>act</c> claim, nested as <c>act.act</c>. Omitted when <see langword="null"/>.</param>
    /// <returns>A new JsonObject suitable for <see cref="AuthTokenBuilder.Act"/>.</returns>
    /// <example>
    /// Input: upstreamAgentId = "aauth:asst@example", upstreamChain = null
    /// Output: { "agent": "aauth:asst@example" }
    /// </example>
    public static JsonObject BuildNestedAct(string upstreamAgentId, JsonObject? upstreamChain = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAgentId);

        var node = new JsonObject { ["agent"] = upstreamAgentId };
        if (upstreamChain is not null)
            node["act"] = upstreamChain.DeepClone();
        return node;
    }

    /// <summary>
    /// Validate that a constructed act chain is semantically consistent:
    /// each level has an <c>agent</c> and nested levels don't exceed max depth.
    /// </summary>
    /// <param name="act">The act claim to validate.</param>
    /// <param name="maxDepth">Maximum allowed nesting depth (default 10).</param>
    /// <returns><c>true</c> if valid; <c>false</c> if missing agent or too deep.</returns>
    public static bool ValidateChain(JsonObject act, int maxDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(act);

        var current = act;
        int depth = 0;

        while (current is not null)
        {
            if (++depth > maxDepth)
                return false;

            if (string.IsNullOrEmpty((string?)current["agent"]))
                return false;

            current = current["act"] as JsonObject;
        }

        return true;
    }
}
