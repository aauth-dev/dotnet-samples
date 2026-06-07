using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Headers;
using AAuth.Server.Governance;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Maps the PS governance endpoints (§Mission Creation, §Permission Endpoint,
/// §Audit Endpoint, §Interaction Endpoint) onto seam-driven handlers, mirroring
/// <c>MapAAuthResource</c>. The handlers parse the request with
/// <see cref="AAuth.Server.Governance.GovernanceEndpoints"/>, enforce the
/// <c>mission_terminated</c> rule, and delegate the decision to the registered
/// <see cref="IMissionApprover"/> / <see cref="IPermissionDecider"/> /
/// <see cref="IAuditSink"/> / <see cref="IInteractionRelay"/> seams (registered by
/// <c>AddAAuthGovernance</c>).
/// </summary>
/// <remarks>
/// A <see cref="PermissionOutcome.Prompt"/> / <see cref="MissionApprovalOutcome.Prompt"/>
/// outcome is resolved synchronously (a permission denial / a mission decline)
/// UNLESS an <see cref="IDeferredConsentStore"/> is registered (via
/// <c>AddAAuthDeferredConsent</c>): with the store, the mapper parks the request,
/// answers <c>202 Accepted</c> with a poll <c>Location</c>, and resolves it once
/// the user decides (§Deferred Consent). The PS still owns the browser consent
/// page that records the user's decision via
/// <see cref="IDeferredConsentStore.ResolveAsync"/>; the mapper only emits the
/// 202 + poll route and completes the parked decision.
/// </remarks>
public static class AAuthGovernanceApplicationBuilderExtensions
{
    /// <summary>
    /// Map the mission, permission, audit, and interaction governance endpoints
    /// (plus the deferred-consent poll route) using the DI-registered seams. Call
    /// <c>AddAAuthGovernance(...)</c> first.
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

        endpoints.MapPost(options.Resolve(options.MissionPath),
            (HttpContext ctx, IMissionStore missions, IMissionApprover approver) =>
                HandleMissionAsync(ctx, options, missions, approver));
        endpoints.MapPost(options.Resolve(options.PermissionPath),
            (HttpContext ctx, IMissionStore missions, IMissionLog log, IPermissionDecider decider) =>
                HandlePermissionAsync(ctx, options, missions, log, decider));
        endpoints.MapPost(options.Resolve(options.AuditPath), HandleAuditAsync);
        endpoints.MapPost(options.Resolve(options.InteractionPath),
            (HttpContext ctx, IMissionStore missions, IMissionLog log, IInteractionRelay relay) =>
                HandleInteractionAsync(ctx, options, missions, log, relay));
        endpoints.MapGet(options.Resolve(options.PendingPath).TrimEnd('/') + "/{id}",
            (HttpContext ctx, string id, IMissionStore missions, IMissionLog log) =>
                HandlePendingAsync(ctx, id, options, missions, log));

        return endpoints;
    }

    private static async Task<IResult> HandleMissionAsync(
        HttpContext ctx,
        AAuthGovernancePipelineOptions options,
        IMissionStore missions,
        IMissionApprover approver)
    {
        var verification = ctx.GetAAuthVerification();
        if (verification?.TokenType != AAuthTokenType.AgentToken || string.IsNullOrEmpty(verification.Agent))
        {
            return Results.Json(new { error = "invalid_carrier_token" }, statusCode: StatusCodes.Status401Unauthorized);
        }

        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        if (body is null)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        MissionProposal proposal;
        try
        {
            proposal = GovernanceEndpoints.ParseMissionProposal(body);
        }
        catch (FormatException)
        {
            return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
        }

        var approverUrl = ResolveApprover(ctx, options);
        var decision = await approver.ApproveAsync(
            new MissionApprovalContext(verification.Agent, approverUrl, proposal), ctx.RequestAborted).ConfigureAwait(false);

        switch (decision.Outcome)
        {
            case MissionApprovalOutcome.Declined:
                return Results.Json(
                    new { error = "access_denied", detail = decision.Message },
                    statusCode: StatusCodes.Status403Forbidden);

            case MissionApprovalOutcome.Prompt:
            {
                var store = ctx.RequestServices.GetService<IDeferredConsentStore>();
                if (store is null)
                {
                    // No user channel: a prompt cannot be resolved — decline.
                    return Results.Json(
                        new { error = "access_denied" }, statusCode: StatusCodes.Status403Forbidden);
                }
                var parked = await store.ParkAsync(new DeferredConsent
                {
                    Kind = DeferredConsentKind.MissionCreation,
                    Agent = verification.Agent,
                    Approver = approverUrl,
                    Proposal = proposal,
                }, ctx.RequestAborted).ConfigureAwait(false);
                return DeferredAccepted(ctx, options, parked.Id);
            }

            default:
                return await CompleteMissionAsync(
                    ctx, missions, approverUrl, verification.Agent, proposal, decision.ApprovedTools)
                    .ConfigureAwait(false);
        }
    }

    private static async Task<IResult> HandlePermissionAsync(
        HttpContext ctx,
        AAuthGovernancePipelineOptions options,
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

        // A Prompt defers to the user when a deferred-consent store is registered;
        // otherwise the mapper has no user channel and resolves it as a denial.
        if (decision.Outcome == PermissionOutcome.Prompt)
        {
            var store = ctx.RequestServices.GetService<IDeferredConsentStore>();
            if (store is not null)
            {
                var parked = await store.ParkAsync(new DeferredConsent
                {
                    Kind = DeferredConsentKind.Permission,
                    Approver = ResolveApprover(ctx, options),
                    Permission = request,
                }, ctx.RequestAborted).ConfigureAwait(false);
                return DeferredAccepted(ctx, options, parked.Id);
            }
        }

        var granted = decision.Outcome == PermissionOutcome.Granted;

        if (request.Mission is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.Mission.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
            {
                Action = request.Action.Name,
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
        AAuthGovernancePipelineOptions options,
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
                // interaction / payment: when the relay is still pending the PS
                // MUST return a deferred response and let the agent poll until the
                // user completes (§Interaction Response). Park it on the deferred
                // store and answer 202; without a store there is no user channel,
                // so treat the relay as having resolved synchronously (200).
                if (result.Pending)
                {
                    var store = ctx.RequestServices.GetService<IDeferredConsentStore>();
                    if (store is not null)
                    {
                        var parked = await store.ParkAsync(new DeferredConsent
                        {
                            Kind = DeferredConsentKind.Interaction,
                            Approver = request.Mission?.Approver ?? string.Empty,
                            Interaction = request,
                        }, ctx.RequestAborted).ConfigureAwait(false);
                        return DeferredAccepted(ctx, options, parked.Id);
                    }
                }
                return Results.Json(new { status = "ok" });
        }
    }

    // Resolve a parked deferred consent once the user has decided (§Deferred
    // Consent). Pending → 202 again; approved/declined → the final governance
    // response (mission blob / permission decision / access_denied).
    private static async Task<IResult> HandlePendingAsync(
        HttpContext ctx,
        string id,
        AAuthGovernancePipelineOptions options,
        IMissionStore missions,
        IMissionLog log)
    {
        var store = ctx.RequestServices.GetService<IDeferredConsentStore>();
        if (store is null)
        {
            return Results.NotFound(new { error = "unknown_pending", id });
        }

        var entry = await store.GetAsync(id, ctx.RequestAborted).ConfigureAwait(false);
        if (entry is null)
        {
            return Results.NotFound(new { error = "unknown_pending", id });
        }

        // Hold at 202 until the user decides on the PS consent page.
        if (entry.Decision is null)
        {
            return DeferredAccepted(ctx, options, id);
        }

        await store.RemoveAsync(id, ctx.RequestAborted).ConfigureAwait(false);

        if (entry.Kind == DeferredConsentKind.MissionCreation)
        {
            if (!entry.Decision.Value)
            {
                ctx.Response.Headers.CacheControl = "no-store";
                return Results.Json(
                    new { error = "access_denied", detail = "the user declined this mission" },
                    statusCode: StatusCodes.Status403Forbidden);
            }
            var proposal = entry.Proposal!;
            return await CompleteMissionAsync(
                ctx, missions, entry.Approver, entry.Agent, proposal, proposal.Tools).ConfigureAwait(false);
        }

        if (entry.Kind == DeferredConsentKind.Interaction)
        {
            // The user completed the relayed interaction / payment; the poll loop
            // terminates with the relay's final response (§Interaction Response).
            // The interaction was already recorded in the mission log when it was
            // relayed, so no further bookkeeping is needed here.
            return Results.Json(new { status = "ok" });
        }

        // Permission: the endpoint always returns a decision (200), never access_denied.
        var request = entry.Permission!;
        var granted = entry.Decision.Value;
        if (request.Mission is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.Mission.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
            {
                Action = request.Action.Name,
                Granted = granted,
                Detail = PermissionDecisionReason.OutOfScope.ToString(),
            }).ConfigureAwait(false);
        }
        return Results.Json(new
        {
            permission = granted ? "granted" : "denied",
            reason = granted ? "The user approved." : "The user declined.",
        });
    }

    // Build the verbatim approval blob, persist the mission, and answer with the
    // blob bytes + the AAuth-Mission header (§Mission Approval).
    private static async Task<IResult> CompleteMissionAsync(
        HttpContext ctx,
        IMissionStore missions,
        string approver,
        string agent,
        MissionProposal proposal,
        IReadOnlyList<MissionTool> approvedTools)
    {
        var (blob, s256) = MissionApprovalBuilder.Build(
            approver, agent, proposal, approvedTools, DateTimeOffset.UtcNow);
        await missions.SaveAsync(new StoredMission(s256, approver, agent, blob)).ConfigureAwait(false);
        ctx.Response.Headers[AAuthMissionHeader.Name] =
            AAuthMissionHeader.FormatStructured(approver, s256);
        return Results.Bytes(blob, "application/json");
    }

    // Emit a 202 Accepted with a poll Location (and, when configured, an
    // interaction requirement header) for a parked deferred consent.
    private static IResult DeferredAccepted(
        HttpContext ctx, AAuthGovernancePipelineOptions options, string pendingId)
    {
        var pollPath = options.Resolve(options.PendingPath).TrimEnd('/') + "/" + pendingId;
        ctx.Response.Headers.Location = pollPath;
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers.CacheControl = "no-store";
        if (!string.IsNullOrEmpty(options.InteractionUrl))
        {
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format(options.InteractionUrl, pendingId);
        }
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // The PS's canonical approver URL: the configured Approver, else the request origin.
    private static string ResolveApprover(HttpContext ctx, AAuthGovernancePipelineOptions options)
        => string.IsNullOrEmpty(options.Approver)
            ? $"{ctx.Request.Scheme}://{ctx.Request.Host}"
            : options.Approver;

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
