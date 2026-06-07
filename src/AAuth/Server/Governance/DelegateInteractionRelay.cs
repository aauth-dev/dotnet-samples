using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// An <see cref="IInteractionRelay"/> backed by a delegate, so a PS can supply a
/// user channel with a lambda instead of a full class (§Interaction Endpoint). The
/// delegate receives the parsed <see cref="InteractionRequest"/> and returns the
/// <see cref="InteractionRelayResult"/> outcome.
/// </summary>
public sealed class DelegateInteractionRelay : IInteractionRelay
{
    private readonly Func<InteractionRequest, CancellationToken, Task<InteractionRelayResult>> _relay;

    /// <summary>Create a relay from an async delegate.</summary>
    public DelegateInteractionRelay(Func<InteractionRequest, CancellationToken, Task<InteractionRelayResult>> relay)
    {
        _relay = relay ?? throw new ArgumentNullException(nameof(relay));
    }

    /// <inheritdoc />
    public Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _relay(request, ct);
    }
}
