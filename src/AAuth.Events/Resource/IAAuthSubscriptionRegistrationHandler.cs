namespace AAuth.Events.Resource;

/// <summary>Application policy callback for a verified subscription registration.</summary>
public interface IAAuthSubscriptionRegistrationHandler
{
    /// <summary>
    /// Applies public channel policy or atomically validates/consumes a
    /// protected ticket and persists the subscription.
    /// </summary>
    /// <remarks>
    /// The callback is not invoked when cryptographic verification fails.
    /// Protected implementations must validate the ticket's binding to
    /// <see cref="VerifiedSubscriptionRegistration.AgentSubject"/>,
    /// <see cref="VerifiedSubscriptionRegistration.ResourceAudience"/>, and
    /// <see cref="SubscriptionEndpointContext"/> before consuming it.
    /// </remarks>
    ValueTask<SubscriptionRegistrationResult> RegisterAsync(
        SubscriptionEndpointContext endpoint,
        VerifiedSubscriptionRegistration registration,
        SignatureUnboundRegistrationBody? preferences,
        CancellationToken cancellationToken = default);
}
