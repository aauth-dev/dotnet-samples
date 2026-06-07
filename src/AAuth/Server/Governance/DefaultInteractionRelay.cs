using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IInteractionRelay"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own user channel. It has no way
/// to reach the user, so it returns a benign, non-pending result: questions get an
/// empty answer and completion proposals are treated as not accepted (the mission
/// stays active). A PS that can reach the user MUST override this (§Interaction
/// Endpoint).
/// </summary>
public sealed class DefaultInteractionRelay : IInteractionRelay
{
    /// <inheritdoc />
    public Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(request.Type switch
        {
            InteractionType.Question => new InteractionRelayResult { Answer = string.Empty },
            InteractionType.Completion => new InteractionRelayResult { Accepted = false },
            _ => new InteractionRelayResult { Pending = false },
        });
    }
}
