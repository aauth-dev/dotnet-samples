namespace AAuth.Events.Resource;

/// <summary>Default outcome categories for subscription registration.</summary>
public enum SubscriptionRegistrationStatus
{
    Accepted = 200,
    Malformed = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    Conflict = 409,
}

/// <summary>Application result mapped by the endpoint adapter.</summary>
public sealed record SubscriptionRegistrationResult(
    SubscriptionRegistrationStatus Status,
    IReadOnlyList<string>? SelectedEventTypes = null,
    string? Detail = null)
{
    /// <summary>Returns a successful registration and its selected event types.</summary>
    public static SubscriptionRegistrationResult Accepted(IEnumerable<string> selectedEventTypes) =>
        new(SubscriptionRegistrationStatus.Accepted,
            (selectedEventTypes ?? throw new ArgumentNullException(nameof(selectedEventTypes))).ToArray());
    /// <summary>Alias for <see cref="Accepted"/>.</summary>
    public static SubscriptionRegistrationResult Ok(IEnumerable<string> selectedEventTypes) =>
        Accepted(selectedEventTypes);
    /// <summary>Returns a malformed request result.</summary>
    public static SubscriptionRegistrationResult BadRequest(string? detail = null) =>
        new(SubscriptionRegistrationStatus.Malformed, Detail: detail);
    /// <summary>Returns an unauthorized result.</summary>
    public static SubscriptionRegistrationResult Unauthorized(string? detail = null) =>
        new(SubscriptionRegistrationStatus.Unauthorized, Detail: detail);
    /// <summary>Returns a forbidden result.</summary>
    public static SubscriptionRegistrationResult Forbidden(string? detail = null) =>
        new(SubscriptionRegistrationStatus.Forbidden, Detail: detail);
    /// <summary>Returns a not-found result.</summary>
    public static SubscriptionRegistrationResult NotFound(string? detail = null) =>
        new(SubscriptionRegistrationStatus.NotFound, Detail: detail);
    /// <summary>Returns a duplicate or reused-ticket conflict.</summary>
    public static SubscriptionRegistrationResult Conflict(string? detail = null) =>
        new(SubscriptionRegistrationStatus.Conflict, Detail: detail);
}
