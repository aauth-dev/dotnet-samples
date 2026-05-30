using System;

namespace AAuth.Errors;

/// <summary>
/// Thrown when the Person Server's token endpoint rejects a token exchange
/// with a structured error response (§Token Endpoint Error Response Format).
/// </summary>
/// <remarks>
/// The PS returns a non-2xx response whose JSON body carries an
/// <c>error</c> code (REQUIRED) and an optional <c>error_description</c>.
/// This typed exception surfaces those fields so callers (UIs, retry
/// policies, tests) can branch on the error code without re-parsing the
/// body. Responses that are not parseable AAuth error objects fall back to
/// a plain <see cref="System.Net.Http.HttpRequestException"/> instead.
/// <para>
/// Polling-phase terminal errors (after a <c>202</c> deferred response) are
/// surfaced separately via <see cref="PollingErrorException"/>.
/// </para>
/// </remarks>
public sealed class AAuthTokenExchangeException : Exception
{
    /// <summary>The wire <c>error</c> code (e.g. <c>invalid_resource_token</c>).</summary>
    public string ErrorCode { get; }

    /// <summary>The optional human-readable <c>error_description</c>, if present.</summary>
    public string? ErrorDescription { get; }

    /// <summary>The HTTP status code from the token endpoint response.</summary>
    public int StatusCode { get; }

    /// <summary>
    /// <see langword="true"/> when the error is not retryable as-is (the agent,
    /// resource, or request must change). <see langword="false"/> for transient
    /// errors (<c>server_error</c>) where a later retry may succeed.
    /// </summary>
    public bool IsTerminal { get; }

    /// <summary>Create a token-exchange exception.</summary>
    public AAuthTokenExchangeException(
        string errorCode, string? errorDescription, int statusCode, bool isTerminal)
        : base(BuildMessage(errorCode, errorDescription, statusCode))
    {
        ErrorCode = errorCode;
        ErrorDescription = errorDescription;
        StatusCode = statusCode;
        IsTerminal = isTerminal;
    }

    /// <summary>
    /// Classify whether a token-endpoint <paramref name="errorCode"/> is terminal.
    /// Only <c>server_error</c> is treated as transient (retryable); every other
    /// known or unknown code is terminal, including <c>user_unreachable</c>
    /// (a hard stop when the PS has no channel to the user and the agent did
    /// not declare the <c>interaction</c> capability).
    /// </summary>
    public static bool IsTerminalCode(string? errorCode)
        => !string.Equals(errorCode, "server_error", StringComparison.Ordinal);

    private static string BuildMessage(string errorCode, string? errorDescription, int statusCode)
        => errorDescription is { Length: > 0 }
            ? $"Token exchange failed: {errorCode} (HTTP {statusCode}) — {errorDescription}"
            : $"Token exchange failed: {errorCode} (HTTP {statusCode})";
}
