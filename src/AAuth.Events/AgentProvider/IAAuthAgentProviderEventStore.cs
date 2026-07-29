using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.AgentProvider;

/// <summary>
/// Durable Agent Provider subscription and inbox boundary.
/// </summary>
/// <remarks>
/// Implementations must make <see cref="AcceptEventAsync"/> one transaction:
/// subscription lookup, resource and audience checks, idempotency lookup, use
/// accounting, and inbox persistence must either all succeed or have no effect.
/// The package intentionally does not provide an in-memory production store.
/// </remarks>
public interface IAAuthAgentProviderEventStore
{
    /// <summary>
    /// Attempts to durably create a subscription. <see langword="false"/> means
    /// that the <c>eid</c> already exists and the caller must generate another.
    /// </summary>
    Task<bool> TryCreateSubscriptionAsync(
        AgentProviderSubscription subscription,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically validates, accounts for, and durably accepts an incoming event.
    /// </summary>
    Task<EventAcceptanceResult> AcceptEventAsync(
        IncomingEvent incomingEvent,
        CancellationToken cancellationToken = default);
}
