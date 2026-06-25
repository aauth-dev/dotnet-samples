using System;

namespace AAuth.Errors;

/// <summary>
/// The <c>?error=</c> codes a server returns when it redirects the user's browser
/// to a <c>callback</c> URL after an interaction fails, and their mapping to the
/// polling errors surfaced to the agent (§Interaction Callback Errors).
/// </summary>
/// <remarks>
/// <para>A callback error MUST NOT be treated as completable: a recipient of a
/// callback carrying an <c>error</c> parameter abandons the pending request and
/// surfaces the error to the caller. In the resource-initiated interaction flow
/// (§Resource-Initiated Interaction) the PS maps the received callback error to a
/// polling error returned to the agent; an agent that registers a browser
/// <c>callback_endpoint</c> uses the same mapping to normalise a redirect into the
/// polling-error vocabulary its caller already understands.</para>
/// <para>This is the shared, pure-function mapping; the wiring lives with whichever
/// callback receiver consumes it.</para>
/// </remarks>
public static class InteractionCallbackError
{
    /// <summary>The user explicitly declined the interaction. Maps to <c>denied</c>.</summary>
    public const string AccessDenied = "access_denied";

    /// <summary>The user opened the interaction but made no decision. Maps to <c>abandoned</c>.</summary>
    public const string UserAbandoned = "user_abandoned";

    /// <summary>The party handling the interaction hit an internal failure. Maps to <c>server_error</c>.</summary>
    public const string ServerError = "server_error";

    /// <summary>The interaction service is temporarily unavailable. Maps to <c>server_error</c>.</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>The interaction session expired before completion. Maps to <c>expired</c>.</summary>
    public const string InteractionExpired = "interaction_expired";

    /// <summary>
    /// Map a callback <c>?error=</c> code to the polling error returned to the agent
    /// (§Interaction Callback Errors): <c>access_denied</c> → <see cref="PollingErrorCode.Denied"/>,
    /// <c>user_abandoned</c> → <see cref="PollingErrorCode.Abandoned"/>,
    /// <c>interaction_expired</c> → <see cref="PollingErrorCode.Expired"/>,
    /// <c>server_error</c>/<c>temporarily_unavailable</c> → <see cref="PollingErrorCode.ServerError"/>.
    /// An unrecognised (but present) code defaults to <see cref="PollingErrorCode.ServerError"/> —
    /// an error callback is never completable, so an unknown error fails closed.
    /// </summary>
    public static PollingErrorCode ToPollingError(string errorCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(errorCode);
        return errorCode switch
        {
            AccessDenied => PollingErrorCode.Denied,
            UserAbandoned => PollingErrorCode.Abandoned,
            InteractionExpired => PollingErrorCode.Expired,
            ServerError => PollingErrorCode.ServerError,
            TemporarilyUnavailable => PollingErrorCode.ServerError,
            _ => PollingErrorCode.ServerError,
        };
    }

    /// <summary>
    /// Interpret the <c>error</c> query parameter of a callback redirect. Returns
    /// <see langword="false"/> when no error is present — a success redirect, so the
    /// pending request may proceed. Returns <see langword="true"/> with the mapped
    /// <paramref name="pollingError"/> otherwise; the caller MUST NOT treat the
    /// request as completable and surfaces the error.
    /// </summary>
    /// <param name="errorCode">The raw <c>error</c> query value, or <see langword="null"/>/empty when absent.</param>
    /// <param name="pollingError">The mapped polling error when an error is present.</param>
    public static bool TryGetPollingError(string? errorCode, out PollingErrorCode pollingError)
    {
        if (string.IsNullOrEmpty(errorCode))
        {
            pollingError = default;
            return false;
        }

        pollingError = ToPollingError(errorCode);
        return true;
    }
}
