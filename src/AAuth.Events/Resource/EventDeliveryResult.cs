using System.Net;

namespace AAuth.Events.Resource;

/// <summary>Outcome of an AP event-delivery request.</summary>
public enum EventDeliveryOutcome
{
    Accepted,
    Exhausted,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Error,
}

/// <summary>Typed result returned after an AP response was received.</summary>
public sealed record EventDeliveryResult(
    HttpStatusCode StatusCode,
    EventDeliveryOutcome Outcome,
    long? RemainingUses = null,
    string? ResponseBody = null,
    string? Error = null)
{
    /// <summary>Whether the AP durably accepted this delivery.</summary>
    public bool IsAccepted => Outcome == EventDeliveryOutcome.Accepted;

    /// <summary>Alias for <see cref="IsAccepted"/>.</summary>
    public bool IsSuccess => IsAccepted;

    /// <summary>Whether the AP reports that the subscription is exhausted.</summary>
    public bool IsExhausted => Outcome == EventDeliveryOutcome.Exhausted;

    /// <summary>Alias for <see cref="IsAccepted"/>.</summary>
    public bool Accepted => IsAccepted;

    /// <summary>Creates a normal accepted response.</summary>
    public static EventDeliveryResult AcceptedResult(long? remainingUses = null, string? responseBody = null) =>
        new(HttpStatusCode.Accepted, EventDeliveryOutcome.Accepted, remainingUses, responseBody);

    /// <summary>Creates an exhausted response.</summary>
    public static EventDeliveryResult ExhaustedResult(string? responseBody = null) =>
        new((HttpStatusCode)429, EventDeliveryOutcome.Exhausted, ResponseBody: responseBody);

    /// <summary>HTTP status corresponding to the typed outcome.</summary>
    public HttpStatusCode Status => StatusCode;
}

/// <summary>Raised when an AP response violates the Events response profile.</summary>
public sealed class EventDeliveryProtocolException : Exception
{
    /// <summary>Creates a protocol failure for an AP response.</summary>
    public EventDeliveryProtocolException(
        string message,
        HttpStatusCode? statusCode = null,
        string? responseBody = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }

    /// <summary>HTTP status that carried the malformed response, if available.</summary>
    public HttpStatusCode? StatusCode { get; }
    /// <summary>Raw response body, if available.</summary>
    public string? ResponseBody { get; }
}
