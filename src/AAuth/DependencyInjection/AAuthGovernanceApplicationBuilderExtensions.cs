using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Server.Governance;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Maps the PS governance endpoints (§Permission Endpoint, §Audit Endpoint,
/// §Interaction Endpoint) onto seam-driven handlers, mirroring
/// <c>MapAAuthResource</c>. The handlers parse the request with
/// <see cref="AAuth.Server.Governance.GovernanceEndpoints"/>, enforce the
/// <c>mission_terminated</c> rule, and delegate the decision to the registered
/// <see cref="IPermissionDecider"/> / <see cref="IAuditSink"/> /
/// <see cref="IInteractionRelay"/> seams (registered by <c>AddAAuthGovernance</c>).
/// </summary>
/// <remarks>
/// This first-pass mapper handles the synchronous decision path. A
/// <see cref="PermissionOutcome.Prompt"/> outcome is resolved as a denial because
/// the mapper has no built-in user channel or pending store; a PS that needs an
/// interactive (deferred 202) consent flow should keep custom endpoints or supply
/// a decider that resolves to <see cref="PermissionOutcome.Granted"/> /
/// <see cref="PermissionOutcome.Denied"/> synchronously. The mission-creation
/// endpoint is intentionally not mapped here — building and signing the approval
/// blob and approving the proposal is PS-specific policy.
/// </remarks>
public static class AAuthGovernanceApplicationBuilderExtensions
{
    /// <summary>
    /// Map the permission, audit, and interaction governance endpoints using the
    /// DI-registered seams. Call <c>AddAAuthGovernance(...)</c> first.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder (e.g. the <c>WebApplication</c>).</param>
    /// <param name="configure">Optional route/path configuration.</param>
    /// <returns>The endpoint route builder for chaining.</returns>
    public static IEndpointRouteBuilder MapAAuthGovernance(
        this IEndpointRouteBuilder endpoints,
        Action<AAuthGovernancePipelineOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = new AAuthGovernancePipelineOptions();
        configure?.Invoke(options);

        endpoints.MapPost(options.Resolve(options.PermissionPath), HandlePermissionAsync);
        endpoints.MapPost(options.Resolve(options.AuditPath), HandleAuditAsync);
        endpoints.MapPost(options.Resolve(options.InteractionPath), HandleInteractionAsync);

        return endpoints;
    }

    private static async Task<IResult> HandlePermissionAsync(
        HttpContext ctx,
        IMissionStore missions,
        IMissionLog log,
        IPermissionDecider decider)
    {
        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        if (body is null)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        PermissionRequest request;
        try
        {
            request = GovernanceEndpoints.ParsePermission(body);
        }
        catch (FormatException)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        StoredMission? stored = null;
        IReadOnlyList<MissionLogEntry> history = [];
        if (request.Mission is not null)
        {
            stored = await missions.GetAsync(request.Mission.S256).ConfigureAwait(false);
            if (stored is { State: MissionState.Terminated })
            {
                return GovernanceEndpoints.MissionTerminated();
            }
            history = await log.ReadAsync(request.Mission.S256).ConfigureAwait(false);
        }

        var decision = await decider.DecideAsync(
            new PermissionDecisionContext(request, stored, history), ctx.RequestAborted).ConfigureAwait(false);

        // First-pass mapper has no user channel: a Prompt resolves as a denial.
        var granted = decision.Outcome == PermissionOutcome.Granted;

        if (request.Mission is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.Mission.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
            {
                Action = request.Action,
                Granted = granted,
                Detail = decision.Reason.ToString(),
            }).ConfigureAwait(false);
        }

        return Results.Json(new
        {
            permission = granted ? "granted" : "denied",
            reason = decision.Message ?? decision.Reason.ToString(),
        });
    }

    private static async Task<IResult> HandleAuditAsync(
        HttpContext ctx,
        IMissionStore missions,
        IAuditSink sink)
    {
        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        if (body is null)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        AuditRecord record;
        try
        {
            record = GovernanceEndpoints.ParseAudit(body);
        }
        catch (FormatException)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        var stored = await missions.GetAsync(record.Mission.S256).ConfigureAwait(false);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }

        await sink.RecordAsync(record, ctx.RequestAborted).ConfigureAwait(false);
        return Results.StatusCode(StatusCodes.Status201Created);
    }

    private static async Task<IResult> HandleInteractionAsync(
        HttpContext ctx,
        IMissionStore missions,
        IMissionLog log,
        IInteractionRelay relay)
    {
        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        if (body is null)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        InteractionRequest request;
        try
        {
            request = GovernanceEndpoints.ParseInteraction(body);
        }
        catch (FormatException)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        if (request.Mission is not null)
        {
            var stored = await missions.GetAsync(request.Mission.S256).ConfigureAwait(false);
            if (stored is { State: MissionState.Terminated })
            {
                return GovernanceEndpoints.MissionTerminated();
            }
        }

        var result = await relay.RelayAsync(request, ctx.RequestAborted).ConfigureAwait(false);

        if (request.Mission is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.Mission.S256, MissionLogEntryKind.Interaction, DateTimeOffset.UtcNow)
            {
                Detail = request.Type.ToString(),
            }).ConfigureAwait(false);
        }

        switch (request.Type)
        {
            case InteractionType.Question:
                return Results.Json(new { answer = result.Answer ?? string.Empty });

            case InteractionType.Completion:
                if (result.Accepted == true && request.Mission is not null)
                {
                    await missions.SetStateAsync(request.Mission.S256, MissionState.Terminated).ConfigureAwait(false);
                    return Results.Json(new { mission_status = "terminated" });
                }
                return Results.Json(new { mission_status = "active" });

            default:
                return Results.Json(new { status = "ok" });
        }
    }

    private static async Task<JsonObject?> ReadJsonAsync(HttpContext ctx)
    {
        try
        {
            return await ctx.Request.ReadFromJsonAsync<JsonObject>().ConfigureAwait(false);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
