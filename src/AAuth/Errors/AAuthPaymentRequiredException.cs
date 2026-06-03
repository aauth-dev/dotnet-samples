using System;

namespace AAuth.Errors;

/// <summary>
/// Thrown when an Access Server responds to a Person Server federation
/// request with <c>402 Payment Required</c> (§AS Token Endpoint).
/// </summary>
/// <remarks>
/// The AAuth specification recognises the payment requirement but leaves the
/// payment protocol, settlement mechanism, and billing terms <em>out of
/// scope</em>. This typed exception surfaces the <c>Location</c> (payment URL)
/// and the raw <c>WWW-Authenticate</c> challenge so a caller that understands
/// an external payment scheme (e.g. x402) can settle out of band and retry the
/// federation request. The SDK itself performs no settlement.
/// </remarks>
public sealed class AAuthPaymentRequiredException : Exception
{
    /// <summary>The payment URL from the response <c>Location</c> header, if present.</summary>
    public string? Location { get; }

    /// <summary>The raw <c>WWW-Authenticate</c> challenge value, if present.</summary>
    public string? Challenge { get; }

    /// <summary>Create a payment-required exception.</summary>
    public AAuthPaymentRequiredException(string? location, string? challenge)
        : base(BuildMessage(location))
    {
        Location = location;
        Challenge = challenge;
    }

    private static string BuildMessage(string? location)
        => location is { Length: > 0 }
            ? $"Access Server requires payment (HTTP 402); settle via {location} and retry. Payment settlement is out of scope for AAuth."
            : "Access Server requires payment (HTTP 402); payment settlement is out of scope for AAuth.";
}
