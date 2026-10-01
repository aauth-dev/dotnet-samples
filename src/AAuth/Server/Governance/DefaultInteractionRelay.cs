using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IInteractionRelay"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own user channel. It has no way
/// to reach the user, so it returns <see cref="InteractionRelayResult.Unavailable"/>
/// for interaction, payment, and question requests. Completion proposals are
/// treated as not accepted (the mission stays active). A PS that can reach the
/// user MUST override this (§Interaction Endpoint).
/// </summary>
public sealed class DefaultInteractionRelay : IInteractionRelay
{
    /// <inheritdoc />
    public Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(request.Type switch
        {
            InteractionType.Question => new InteractionRelayResult { Unavailable = true },
            InteractionType.Completion => new InteractionRelayResult { Accepted = false },
            _ => new InteractionRelayResult { Unavailable = true },
        });
    }
}
