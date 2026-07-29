namespace AAuth.Events.AgentProvider;

/// <summary>Result of the AP's one atomic event acceptance operation.</summary>
public enum EventAcceptanceOutcome
{
    /// <summary>The event was durably written and a use was consumed.</summary>
    Accepted,
    /// <summary>The exact compact token was already accepted.</summary>
    AlreadyAccepted,
    /// <summary>No subscription exists for the event's eid.</summary>
    UnknownSubscription,
    /// <summary>The subscription lifetime has elapsed.</summary>
    ExpiredSubscription,
    /// <summary>The event issuer/resource is not the authorized resource.</summary>
    WrongResource,
    /// <summary>The event audience is not the subscribed agent.</summary>
    WrongAudience,
    /// <summary>A finite subscription has no uses remaining.</summary>
    Exhausted,
}

/// <summary>Atomic AP store outcome, including the original retry receipt.</summary>
public sealed record EventAcceptanceResult(
    EventAcceptanceOutcome Outcome,
    IncomingEvent? Receipt = null,
    long? RemainingUses = null)
{
    /// <summary>Alias for <see cref="Outcome"/>.</summary>
    public EventAcceptanceOutcome Status => Outcome;
    /// <summary>Whether the event is accepted or an exact idempotent retry.</summary>
    public bool IsAccepted => Outcome is EventAcceptanceOutcome.Accepted or EventAcceptanceOutcome.AlreadyAccepted;
    /// <summary>Whether this is the idempotent retry outcome.</summary>
    public bool IsAlreadyAccepted => Outcome == EventAcceptanceOutcome.AlreadyAccepted;

    /// <summary>Creates an accepted result.</summary>
    public static EventAcceptanceResult Accepted(IncomingEvent receipt, long? remainingUses = null) =>
        new(EventAcceptanceOutcome.Accepted, receipt ?? throw new ArgumentNullException(nameof(receipt)), remainingUses);

    /// <summary>Creates an idempotent result carrying the original receipt.</summary>
    public static EventAcceptanceResult AlreadyAccepted(IncomingEvent receipt, long? remainingUses = null) =>
        new(EventAcceptanceOutcome.AlreadyAccepted, receipt ?? throw new ArgumentNullException(nameof(receipt)), remainingUses);
}
