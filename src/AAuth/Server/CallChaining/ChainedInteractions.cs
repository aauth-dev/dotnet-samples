using System;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Discovery;
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
        ArgumentException.ThrowIfNullOrWhiteSpace(intermediaryBaseUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(pendingPrefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(interactionPrefix);
        ArgumentNullException.ThrowIfNull(exception);
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
            exception.DownstreamInteraction,
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
        return Results.Json(new { status = "interaction_required" }, statusCode: StatusCodes.Status202Accepted);
    }

    /// <summary>Redirect a browser that presented the intermediary code to the downstream interaction.</summary>
    public static IResult RedirectToDownstream(ChainedInteractionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return Results.Redirect(entry.DownstreamInteraction.BuildUserUrl());
    }
}
