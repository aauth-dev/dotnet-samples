using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace AAuth.Tokens;

/// <summary>
/// Utilities to read and walk the nested <c>act</c> delegation chain in auth tokens.
/// </summary>
public static class ActChainReader
{
    /// <summary>
    /// Extract the full delegation chain from a token's <c>act</c> claim.
    /// Returns agent identifiers in order from outermost (immediate caller)
    /// to innermost (original requester).
    /// </summary>
    /// <param name="payload">The decoded JWT payload containing the <c>act</c> claim.</param>
    /// <param name="maxDepth">Maximum traversal depth (default 10).</param>
    /// <returns>List of <c>act.sub</c> values from outer to inner.</returns>
    /// <exception cref="InvalidOperationException">Thrown if depth exceeds <paramref name="maxDepth"/> or act.sub is missing.</exception>
    public static IReadOnlyList<string> GetDelegationChain(JsonObject payload, int maxDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var chain = new List<string>();
        var current = payload["act"] as JsonObject;

        while (current is not null)
        {
            if (chain.Count >= maxDepth)
                throw new InvalidOperationException(
                    $"Act chain depth exceeds maximum allowed ({maxDepth}).");

            var sub = (string?)current["sub"]
                ?? throw new InvalidOperationException("Act claim is missing required 'sub' field.");

            chain.Add(sub);
            current = current["act"] as JsonObject;
        }

        return chain;
    }

    /// <summary>Get the immediate actor (<c>act.sub</c>).</summary>
    /// <returns>The immediate actor's identifier, or null if no <c>act</c> claim.</returns>
    public static string? GetImmediateActor(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var act = payload["act"] as JsonObject;
        return (string?)act?["sub"];
    }

    /// <summary>Get the original requester (innermost <c>act.sub</c>).</summary>
    /// <returns>The original actor's identifier, or null if no <c>act</c> claim.</returns>
    public static string? GetOriginalActor(JsonObject payload, int maxDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var current = payload["act"] as JsonObject;
        if (current is null) return null;

        string? last = null;
        int depth = 0;
        while (current is not null)
        {
            if (++depth > maxDepth)
                throw new InvalidOperationException(
                    $"Act chain depth exceeds maximum allowed ({maxDepth}).");

            last = (string?)current["sub"];
            current = current["act"] as JsonObject;
        }

        return last;
    }

    /// <summary>Get the chain depth (1 = direct, 2+ = chained).</summary>
    /// <returns>The number of nested <c>act</c> levels, or 0 if no <c>act</c> claim.</returns>
    public static int GetChainDepth(JsonObject payload, int maxDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var current = payload["act"] as JsonObject;
        int depth = 0;
        while (current is not null)
        {
            if (++depth > maxDepth)
                throw new InvalidOperationException(
                    $"Act chain depth exceeds maximum allowed ({maxDepth}).");
            current = current["act"] as JsonObject;
        }
        return depth;
    }
}
