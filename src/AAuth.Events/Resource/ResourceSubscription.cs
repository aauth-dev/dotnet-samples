namespace AAuth.Events.Resource;

/// <summary>
/// Immutable resource-side state for one verified Events subscription.
/// </summary>
public sealed class ResourceSubscription
{
    /// <summary>Creates a validated subscription state.</summary>
    public ResourceSubscription(
        string eid,
        string apIssuer,
        string agentSubject,
        string resourceAudience,
        long? maxUses,
        DateTimeOffset expiresAt,
        long? remainingUses = null)
    {
        Require(eid, nameof(eid));
        Require(apIssuer, nameof(apIssuer));
        Require(agentSubject, nameof(agentSubject));
        Require(resourceAudience, nameof(resourceAudience));
        if (!Uri.TryCreate(apIssuer, UriKind.Absolute, out _))
            throw new ArgumentException("The AP issuer must be an absolute URL.", nameof(apIssuer));
        if (!Uri.TryCreate(resourceAudience, UriKind.Absolute, out _))
            throw new ArgumentException("The resource audience must be an absolute URL.", nameof(resourceAudience));
        if (maxUses is <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxUses), "max_uses must be positive.");
        if (expiresAt <= DateTimeOffset.MinValue)
            throw new ArgumentOutOfRangeException(nameof(expiresAt));
        if (maxUses is null)
        {
            if (remainingUses is not null)
                throw new ArgumentException("Unlimited subscriptions cannot have remaining uses.", nameof(remainingUses));
        }
        else
        {
            var uses = remainingUses ?? maxUses.Value;
            if (uses < 0 || uses > maxUses.Value)
                throw new ArgumentOutOfRangeException(nameof(remainingUses));
            remainingUses = uses;
        }

        Eid = eid;
        ApIssuer = apIssuer;
        AgentSubject = agentSubject;
        ResourceAudience = resourceAudience;
        MaxUses = maxUses;
        ExpiresAt = expiresAt;
        RemainingUses = remainingUses;
    }

    /// <summary>Subscription event identifier (the verified <c>eid</c>).</summary>
    public string Eid { get; }
    /// <summary>Alias for <see cref="Eid"/>.</summary>
    public string EventId => Eid;
    /// <summary>AP issuer that issued the subscription.</summary>
    public string ApIssuer { get; }
    /// <summary>Agent subject bound to the subscription.</summary>
    public string AgentSubject { get; }
    /// <summary>Alias for <see cref="AgentSubject"/>.</summary>
    public string Agent => AgentSubject;
    /// <summary>Resource audience/issuer bound to the subscription.</summary>
    public string ResourceAudience { get; }
    /// <summary>Maximum number of distinct event deliveries, or null for unlimited.</summary>
    public long? MaxUses { get; }
    /// <summary>Application policy expiry for this stored subscription.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Uses available when this state was created, or null when unlimited.</summary>
    public long? RemainingUses { get; }

    /// <summary>Maps verified registration facts into resource state.</summary>
    /// <remarks>
    /// The application policy expiry is independent of the subscribe-token
    /// registration window and may be later than the verified token expiry.
    /// </remarks>
    public static ResourceSubscription FromRegistration(
        VerifiedSubscriptionRegistration registration,
        DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (registration.ExpiresAt <= registration.IssuedAt)
            throw new ArgumentException("The registration lifetime is invalid.", nameof(registration));
        if (expiresAt <= registration.IssuedAt)
            throw new ArgumentOutOfRangeException(
                nameof(expiresAt), "The subscription expiry must be after registration issue time.");
        return new ResourceSubscription(
            registration.Eid,
            registration.ApIssuer,
            registration.AgentSubject,
            registration.ResourceAudience,
            registration.MaxUses,
            expiresAt);
    }

    private static void Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("The value must not be blank.", parameterName);
    }
}
