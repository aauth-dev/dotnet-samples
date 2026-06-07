using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent.Governance;

/// <summary>
/// Optional deferred-handling callbacks shared by the PS governance clients
/// (mission, permission, interaction). A governance request may trigger a
/// <c>202 Accepted</c> while the PS reaches the user; these callbacks let the
/// agent participate in the clarification chat (#clarification-chat) or relay an
/// interaction it cannot satisfy directly (#user-interaction).
/// </summary>
public sealed class GovernanceOptions
{
    /// <summary>
    /// Invoked when the PS returns <c>requirement=interaction</c> — the agent
    /// must relay the URL/code to the user. When <see langword="null"/> and the
    /// PS defers with an interaction requirement, the request fails.
    /// </summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; init; }

    /// <summary>
    /// Invoked when the PS returns <c>requirement=clarification</c> during review
    /// (§Clarification Chat). Returns the agent's decision (respond / update /
    /// cancel). When <see langword="null"/> and the PS asks for clarification,
    /// the request fails.
    /// </summary>
    public Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? OnClarificationRequired { get; init; }

    /// <summary>Maximum clarification rounds before the exchange aborts (default 5).</summary>
    public int MaxClarificationRounds { get; init; } = ClarificationExchange.DefaultMaxRounds;

    /// <summary>Optional polling tuning for deferred responses.</summary>
    public DeferredPollerOptions? PollerOptions { get; init; }

    // Adapt the public governance options to the shared transport options.
    // Governance never forces an interaction callback and has no post-poll hook.
    internal DeferredExchangeOptions ToExchangeOptions()
        => new()
        {
            OnInteractionRequired = OnInteractionRequired,
            OnClarificationRequired = OnClarificationRequired,
            MaxClarificationRounds = MaxClarificationRounds,
            PollerOptions = PollerOptions,
        };
}
