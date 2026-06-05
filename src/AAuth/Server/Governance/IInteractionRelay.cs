using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// The result of relaying an interaction to the user through the PS (§Interaction
/// Response). Populated fields depend on the request <see cref="InteractionType"/>.
/// </summary>
public sealed record InteractionRelayResult
{
    /// <summary>The user's answer (for <c>question</c>).</summary>
    public string? Answer { get; init; }

    /// <summary>
    /// Whether the user accepted mission completion (for <c>completion</c>). When
    /// <see langword="true"/> the PS terminates the mission; when
    /// <see langword="false"/> the mission remains active.
    /// </summary>
    public bool? Accepted { get; init; }

    /// <summary>
    /// Whether the relay is still pending — the PS should return a deferred
    /// response and let the agent poll (for <c>interaction</c> / <c>payment</c>).
    /// </summary>
    public bool Pending { get; init; }
}

/// <summary>
/// PS-side relay seam for the interaction endpoint (§Interaction Endpoint): reach
/// the user to relay an interaction/payment, ask a question, or present a
/// completion summary. The SDK supplies the contract; the PS implements the
/// user channel.
/// </summary>
public interface IInteractionRelay
{
    /// <summary>Relay <paramref name="request"/> to the user and return the outcome.</summary>
    Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default);
}
