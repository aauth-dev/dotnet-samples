using System;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.CallChaining;

/// <summary>Serializable state for an intermediary-owned chained interaction.</summary>
public sealed record ChainedInteractionEntry(
    string Id,
    string Code,
    string InteractionUrl,
    string PendingUrl,
    Interaction DownstreamInteraction,
    string OperationName,
    JsonObject State,
    DateTimeOffset ExpiresAt);

/// <summary>Helpers for §Interaction Chaining responses owned by the intermediary.</summary>
public static class AAuthChainedInteractions
{
    /// <summary>
    /// Park a downstream interaction under an intermediary-owned code and pending URL.
    /// </summary>
    public static ChainedInteractionEntry Park(
        string intermediaryBaseUrl,
        string pendingPrefix,
        string interactionPrefix,
        AAuthInteractionChainedException exception,
        string operationName,
        JsonObject state,
        DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return Park(intermediaryBaseUrl, pendingPrefix, interactionPrefix, exception.DownstreamInteraction,
            operationName, state, expiresAt);
    }

    /// <summary>
    /// Park a downstream interaction (for example <see cref="AAuthChainedOperation{TResult}.Interaction"/>)
    /// under an intermediary-owned code and pending URL.
    /// </summary>
    public static ChainedInteractionEntry Park(
        string intermediaryBaseUrl,
        string pendingPrefix,
        string interactionPrefix,
        Interaction downstreamInteraction,
        string operationName,
        JsonObject state,
        DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(intermediaryBaseUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(pendingPrefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(interactionPrefix);
        ArgumentNullException.ThrowIfNull(downstreamInteraction);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationName);
        ArgumentNullException.ThrowIfNull(state);

        var id = Guid.NewGuid().ToString("N");
        var code = AAuthInteractionCode.Generate(26);
        var baseUrl = intermediaryBaseUrl.TrimEnd('/');
        return new ChainedInteractionEntry(
            id,
            code,
            $"{baseUrl}/{interactionPrefix.Trim('/')}/{id}",
            $"{pendingPrefix.TrimEnd('/')}/{id}",
            downstreamInteraction,
            operationName,
            state,
            expiresAt);
    }

    /// <summary>Emit the intermediary's own <c>202 requirement=interaction</c>.</summary>
    public static IResult Accepted(HttpContext context, ChainedInteractionEntry entry, AAuthEgressPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(entry);
        context.Response.Headers.Location = entry.PendingUrl;
        context.Response.Headers["Retry-After"] = "1";
        context.Response.Headers["Cache-Control"] = "no-store";
        context.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format(entry.InteractionUrl, entry.Code, policy);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    /// <summary>Redirect a browser that presented the intermediary code to the downstream interaction.</summary>
    public static IResult RedirectToDownstream(ChainedInteractionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return Results.Redirect(entry.DownstreamInteraction.BuildUserUrl());
    }

    /// <summary>
    /// Re-key a parked entry for a new downstream interaction (for example an Access Server step after
    /// Person Server consent): a fresh intermediary code, the same id and pending URL. The caller's
    /// interaction handler sees a new user URL and surfaces it again.
    /// </summary>
    public static ChainedInteractionEntry Rekey(ChainedInteractionEntry entry, Interaction downstream)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(downstream);
        return entry with { Code = AAuthInteractionCode.Generate(26), DownstreamInteraction = downstream };
    }

    /// <summary>
    /// Map why a chained operation failed to the §Polling Error Codes response for the intermediary's
    /// pending URL, keeping the downstream <c>detail</c>. Returns <see langword="null"/> for failures
    /// that are not a protocol outcome (the caller answers <c>server_error</c>).
    /// </summary>
    public static IResult? PollingFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception switch
        {
            AAuthInteractionDeniedException denied => AAuthProblemDetails.Polling(PollingErrorCode.Denied,
                (denied.InnerException as PollingErrorException)?.Detail ?? denied.Message),
            AAuthInteractionTimeoutException timeout => AAuthProblemDetails.Polling(PollingErrorCode.Expired, timeout.Message),
            PollingErrorException polling => polling.ErrorCode switch
            {
                PollingErrorCode.Denied or PollingErrorCode.Abandoned or PollingErrorCode.Revoked or PollingErrorCode.Expired
                    or PollingErrorCode.ServerError => AAuthProblemDetails.Polling(polling.ErrorCode, polling.Detail),
                // The downstream pending request is gone; the caller MAY start a fresh request.
                PollingErrorCode.InvalidCode => AAuthProblemDetails.Polling(PollingErrorCode.Expired, polling.Detail),
                _ => null,
            },
            AAuthTokenExchangeException exchange when PollingErrorException.TryParseCode(exchange.ErrorCode, out var code)
                && code is PollingErrorCode.Denied or PollingErrorCode.Abandoned or PollingErrorCode.Revoked or PollingErrorCode.Expired
                => AAuthProblemDetails.Polling(code, exchange.Detail),
            OperationCanceledException => AAuthProblemDetails.Polling(PollingErrorCode.Expired),
            _ => null,
        };
    }
}
