using System;

namespace AAuth.Errors;

/// <summary>
/// Error codes from AAuth polling per §Polling Error Codes.
/// </summary>
public enum PollingErrorCode
{
    /// <summary>User or approver explicitly denied the request. HTTP 403.</summary>
    Denied,

    /// <summary>Interaction code was used but user did not complete. HTTP 403.</summary>
    Abandoned,

    /// <summary>Timed out. HTTP 408.</summary>
    Expired,

    /// <summary>Interaction code not recognized or already consumed. HTTP 410.</summary>
    InvalidCode,

    /// <summary>Polling too frequently — increase interval by 5 seconds. HTTP 429.</summary>
    SlowDown,

    /// <summary>Internal error. HTTP 500.</summary>
    ServerError,
}

/// <summary>
/// Exception thrown when a polling response indicates a terminal or throttled error.
/// </summary>
public sealed class PollingErrorException : Exception
{
    /// <summary>The polling error code.</summary>
    public PollingErrorCode ErrorCode { get; }

    /// <summary>The HTTP status code from the response.</summary>
    public int StatusCode { get; }

    /// <summary>Create a polling error exception.</summary>
    public PollingErrorException(PollingErrorCode errorCode, int statusCode, string? message = null)
        : base(message ?? $"Polling error: {ToWireCode(errorCode)} (HTTP {statusCode})")
    {
        ErrorCode = errorCode;
        StatusCode = statusCode;
    }

    /// <summary>Convert a polling error code to wire format.</summary>
    public static string ToWireCode(PollingErrorCode code) => code switch
    {
        PollingErrorCode.Denied => "denied",
        PollingErrorCode.Abandoned => "abandoned",
        PollingErrorCode.Expired => "expired",
        PollingErrorCode.InvalidCode => "invalid_code",
        PollingErrorCode.SlowDown => "slow_down",
        PollingErrorCode.ServerError => "server_error",
        _ => "server_error",
    };

    /// <summary>Try to parse a wire-format polling error code.</summary>
    public static bool TryParseCode(string? code, out PollingErrorCode result)
    {
        result = code switch
        {
            "denied" => PollingErrorCode.Denied,
            "abandoned" => PollingErrorCode.Abandoned,
            "expired" => PollingErrorCode.Expired,
            "invalid_code" => PollingErrorCode.InvalidCode,
            "slow_down" => PollingErrorCode.SlowDown,
            "server_error" => PollingErrorCode.ServerError,
            _ => default,
        };
        return code is "denied" or "abandoned" or "expired" or "invalid_code"
            or "slow_down" or "server_error";
    }
}
