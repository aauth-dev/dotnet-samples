namespace AAuth.Events.AgentProvider;

/// <summary>Lifecycle state of an Agent Provider subscription.</summary>
public enum AgentProviderSubscriptionStatus
{
    /// <summary>The subscription may accept events.</summary>
    Active,
    /// <summary>The application revoked the subscription.</summary>
    Revoked,
    /// <summary>The subscription lifetime has elapsed.</summary>
    Expired,
    /// <summary>The finite use allowance has been consumed.</summary>
    Exhausted,
}

/// <summary>Durable AP-side state created for one subscribe-token <c>eid</c>.</summary>
public sealed class AgentProviderSubscription
{
    /// <summary>Creates a subscription with zero consumed uses.</summary>
    public AgentProviderSubscription(
        string eid,
        string agent,
        string resource,
        long? maxUses,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(eid)) throw new ArgumentException("A subscription eid is required.", nameof(eid));
        if (string.IsNullOrWhiteSpace(agent)) throw new ArgumentException("A subscription agent is required.", nameof(agent));
        if (string.IsNullOrWhiteSpace(resource)) throw new ArgumentException("A subscription resource is required.", nameof(resource));
        if (maxUses is <= 0) throw new ArgumentOutOfRangeException(nameof(maxUses), "MaxUses must be positive.");
        Eid = eid;
        Agent = agent;
        Resource = resource;
        MaxUses = maxUses;
        ExpiresAt = expiresAt;
    }

    /// <summary>Creates an object initializer-friendly subscription.</summary>
    public AgentProviderSubscription() { }

    /// <summary>Opaque subscription identifier carried by event tokens.</summary>
    public string Eid { get; init; } = string.Empty;
    /// <summary>Agent identifier carried by the subscribe token subject.</summary>
    public string Agent { get; init; } = string.Empty;
    /// <summary>Resource URL authorized by the subscribe token audience.</summary>
    public string Resource { get; init; } = string.Empty;
    /// <summary>Maximum accepted events; <see langword="null"/> means unlimited.</summary>
    public long? MaxUses { get; init; }
    /// <summary>Number of uses already committed by the durable store.</summary>
    public long UseCount { get; set; }
    /// <summary>Application-selected subscription expiry.</summary>
    public DateTimeOffset ExpiresAt { get; init; }
    /// <summary>Current durable lifecycle state.</summary>
    public AgentProviderSubscriptionStatus Status { get; set; } = AgentProviderSubscriptionStatus.Active;

    /// <summary>Alias for <see cref="Agent"/>.</summary>
    public string AgentId => Agent;
    /// <summary>Alias for <see cref="Resource"/>.</summary>
    public string ResourceUrl => Resource;
    /// <summary>Alias for <see cref="UseCount"/>.</summary>
    public long Uses => UseCount;
}
