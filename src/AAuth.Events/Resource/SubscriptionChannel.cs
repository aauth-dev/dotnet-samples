using System.Collections.ObjectModel;

namespace AAuth.Events.Resource;

/// <summary>Whether a subscription channel is open or ticket protected.</summary>
public enum SubscriptionChannelAccess
{
    Public,
    Protected,
}

/// <summary>Describes one resource-owned subscription channel.</summary>
/// <remarks>
/// The channel descriptor is application policy, not authorization. In
/// particular, event types returned by a registration handler must be members
/// of <see cref="AllowedEventTypes"/>. The request body is never used to
/// expand this set.
/// </remarks>
public sealed class SubscriptionChannel
{
    /// <summary>Creates a channel descriptor.</summary>
    public SubscriptionChannel(
        string name,
        string endpointPattern,
        bool isProtected,
        IEnumerable<string> allowedEventTypes,
        string? resourceAudience = null,
        string ticketRouteValueName = "ticket")
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A channel name is required.", nameof(name));
        if (string.IsNullOrWhiteSpace(endpointPattern)) throw new ArgumentException("An endpoint pattern is required.", nameof(endpointPattern));
        ArgumentNullException.ThrowIfNull(allowedEventTypes);
        if (string.IsNullOrWhiteSpace(ticketRouteValueName))
            throw new ArgumentException("A ticket route value name is required.", nameof(ticketRouteValueName));
        var types = allowedEventTypes.Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal).ToArray();
        if (types.Length == 0) throw new ArgumentException("At least one event type is required.", nameof(allowedEventTypes));
        Name = name;
        EndpointPattern = endpointPattern;
        IsProtected = isProtected;
        AllowedEventTypes = new ReadOnlyCollection<string>(types);
        ResourceAudience = resourceAudience;
        TicketRouteValueName = ticketRouteValueName;
    }

    /// <summary>Creates a channel with an explicit access designation.</summary>
    public SubscriptionChannel(
        string name,
        string endpointPattern,
        SubscriptionChannelAccess access,
        IEnumerable<string> allowedEventTypes,
        string? resourceAudience = null,
        string ticketRouteValueName = "ticket")
        : this(name, endpointPattern, access == SubscriptionChannelAccess.Protected,
            allowedEventTypes, resourceAudience, ticketRouteValueName)
    {
    }

    /// <summary>Channel name from the published AsyncAPI document.</summary>
    public string Name { get; }
    /// <summary>ASP.NET route pattern for registration.</summary>
    public string EndpointPattern { get; }
    /// <summary>Whether this channel requires a pre-authorized ticket.</summary>
    public bool IsProtected { get; }
    /// <summary>Whether this channel is public.</summary>
    public bool IsPublic => !IsProtected;
    /// <summary>Explicit public/protected access designation.</summary>
    public SubscriptionChannelAccess Access =>
        IsProtected ? SubscriptionChannelAccess.Protected : SubscriptionChannelAccess.Public;
    /// <summary>Event types this channel is allowed to register.</summary>
    public IReadOnlyList<string> AllowedEventTypes { get; }
    /// <summary>Expected subscribe-token resource audience, when configured.</summary>
    public string? ResourceAudience { get; }
    /// <summary>Route-value key containing an opaque protected ticket.</summary>
    public string TicketRouteValueName { get; }

    /// <summary>Creates a public channel.</summary>
    public static SubscriptionChannel Public(
        string name, string endpointPattern, IEnumerable<string> allowedEventTypes, string? resourceAudience = null) =>
        new(name, endpointPattern, false, allowedEventTypes, resourceAudience);

    /// <summary>Creates a protected channel.</summary>
    public static SubscriptionChannel Protected(
        string name, string endpointPattern, IEnumerable<string> allowedEventTypes, string? resourceAudience = null) =>
        new(name, endpointPattern, true, allowedEventTypes, resourceAudience);
}

/// <summary>Request context supplied to a subscription registration handler.</summary>
public sealed record SubscriptionEndpointContext(
    SubscriptionChannel Descriptor,
    IReadOnlyDictionary<string, string?> RouteValues,
    string? Ticket)
{
    /// <summary>Alias for the channel descriptor.</summary>
    public SubscriptionChannel Channel => Descriptor;
}
