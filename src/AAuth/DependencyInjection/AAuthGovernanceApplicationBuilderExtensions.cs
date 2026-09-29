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
        endpoints.MapPost(options.Resolve(options.MissionPath).TrimEnd('/') + "/{missionS256}",
            (HttpContext ctx, string missionS256, IMissionStore missions, IMissionLog log, IInteractionRelay relay) =>
                HandleMissionActionAsync(ctx, missionS256, options, missions, log, relay));
        endpoints.MapPost(options.Resolve(options.PermissionPath),
            (HttpContext ctx, IMissionStore missions, IMissionLog log, IPermissionDecider decider) =>
                HandlePermissionAsync(ctx, options, missions, log, decider));
        endpoints.MapPost(options.Resolve(options.AuditPath), HandleAuditAsync);
        endpoints.MapPost(options.Resolve(options.InteractionPath),
            (HttpContext ctx, IMissionStore missions, IMissionLog log, IInteractionRelay relay) =>
                HandleInteractionAsync(ctx, options, missions, log, relay));
        endpoints.MapMethods(options.Resolve(options.PendingPath).TrimEnd('/') + "/{id}", ["GET", "DELETE"],
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
        if (verification is not { TokenType: AAuthTokenType.AgentToken, IssuerVerified: true, Agent: not null,
            Issuer: not null, Jkt: not null })
        {
            // The signature already verified (this is past the verification
            // middleware); presenting a non-agent token is a semantic authorization
            // refusal, not a signature-authentication failure, so it is a 403 — the
            // §Error Responses 401/`Signature-Error` rule is reserved for the
            // §Verification (Server) signature-failure steps.
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "The mission endpoint requires an agent token.", statusCode: StatusCodes.Status403Forbidden);
        }

        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        if (body is null)
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        MissionProposal proposal;
        try
        {
            proposal = GovernanceEndpoints.ParseMissionProposal(body);
        }
        catch (FormatException)
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        var personServer = ResolvePersonServer(ctx, options);
        var decision = await approver.ApproveAsync(
            new MissionApprovalContext(verification.Agent, personServer, proposal), ctx.RequestAborted).ConfigureAwait(false);

        switch (decision.Outcome)
        {
            case MissionApprovalOutcome.Declined:
                return AAuth.Server.AAuthProblemDetails.Create("denied", decision.Message, statusCode: StatusCodes.Status403Forbidden);

            case MissionApprovalOutcome.Prompt:
            {
                var store = ctx.RequestServices.GetService<IDeferredConsentStore>();
                if (store is null)
                {
                    // No user channel: a prompt cannot be resolved — decline.
                    return AAuth.Server.AAuthProblemDetails.Create("denied", statusCode: StatusCodes.Status403Forbidden);
                }
                var parked = await store.ParkAsync(new DeferredConsent
                {
                    Kind = DeferredConsentKind.MissionCreation,
                    Agent = verification.Agent,
                    OwnerIssuer = verification.Issuer,
                    OwnerKeyThumbprint = verification.Jkt,
                    PersonServer = personServer,
                    Proposal = proposal,
                    MissionExpiresAt = decision.ExpiresAt,
                }, ctx.RequestAborted).ConfigureAwait(false);
                return DeferredAccepted(ctx, options, parked);
            }

            default:
                return await CompleteMissionAsync(
                    ctx, missions, personServer, verification.Agent, proposal, decision.ApprovedTools, decision.ExpiresAt)
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
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        PermissionRequest request;
        try
        {
            request = GovernanceEndpoints.ParsePermission(body);
        }
        catch (FormatException)
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        StoredMission? stored = null;
        IReadOnlyList<MissionLogEntry> history = [];
        if (request.MissionS256 is not null)
        {
            stored = await missions.GetAsync(request.MissionS256).ConfigureAwait(false);
        }
        if (GovernanceEndpoints.Authorize(ctx, request.MissionS256, stored) is { } denied) return denied;
        if (request.MissionS256 is not null)
        {
            history = await log.ReadAsync(request.MissionS256).ConfigureAwait(false);
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
                    Agent = ctx.GetAAuthVerification()!.Agent!,
                    OwnerIssuer = ctx.GetAAuthVerification()!.Issuer,
                    OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt,
                    PersonServer = ResolvePersonServer(ctx, options),
                    Permission = request,
                }, ctx.RequestAborted).ConfigureAwait(false);
                return DeferredAccepted(ctx, options, parked);
            }
        }

        var granted = decision.Outcome == PermissionOutcome.Granted;

        if (request.MissionS256 is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.MissionS256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
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
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        AuditRecord record;
        try
        {
            record = GovernanceEndpoints.ParseAudit(body);
        }
        catch (FormatException)
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        var stored = await missions.GetAsync(record.MissionS256).ConfigureAwait(false);
        if (GovernanceEndpoints.Authorize(ctx, record.MissionS256, stored) is { } denied) return denied;

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
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        InteractionRequest request;
        try
        {
            request = GovernanceEndpoints.ParseInteraction(body);
        }
        catch (FormatException)
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        }

        var stored = request.MissionS256 is null ? null
            : await missions.GetAsync(request.MissionS256).ConfigureAwait(false);
        if (GovernanceEndpoints.Authorize(ctx, request.MissionS256, stored) is { } denied) return denied;

        var result = await relay.RelayAsync(request, ctx.RequestAborted).ConfigureAwait(false);

        // §Interaction Endpoint Errors: the PS has no channel to relay this specific
        // interaction/payment. Non-terminal — the agent falls back to directing the
        // user itself. Distinct from the terminal user_unreachable.
        if (result.Unavailable)
        {
            return AAuth.Server.AAuthProblemDetails.Create("interaction_unavailable", statusCode: StatusCodes.Status424FailedDependency);
        }

        if (request.MissionS256 is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.MissionS256, MissionLogEntryKind.Interaction, DateTimeOffset.UtcNow)
            {
                Detail = request.Type.ToString(),
            }).ConfigureAwait(false);
        }

        switch (request.Type)
        {
            case InteractionType.Question:
                return Results.Json(new { answer = result.Answer ?? string.Empty });

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
                            Agent = ctx.GetAAuthVerification()!.Agent!,
                            OwnerIssuer = ctx.GetAAuthVerification()!.Issuer,
                            OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt,
                            PersonServer = ResolvePersonServer(ctx, options),
                            Interaction = request,
                        }, ctx.RequestAborted).ConfigureAwait(false);
                        return DeferredAccepted(ctx, options, parked);
                    }
                }
                return Results.Json(new { status = "ok" });
        }
    }

    // Resolve a parked deferred consent once the user has decided (§Deferred
    // Consent). Pending → 202 again; approved/declined → the final governance
    // response (mission blob / permission decision / denied).
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
            return AAuth.Server.AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound,
                extensions: new Dictionary<string, object?> { ["id"] = id });
        }

        var entry = await store.GetAsync(id, ctx.RequestAborted).ConfigureAwait(false);
        if (entry is null)
        {
            return AAuth.Server.DeferredState.Missing(id);
        }
        var verified = ctx.GetAAuthVerification();
        if (verified is not { TokenType: AAuthTokenType.AgentToken, IssuerVerified: true }
            || entry.OwnerIssuer is null || entry.OwnerKeyThumbprint is null
            || verified.Issuer != entry.OwnerIssuer || verified.Agent != entry.Agent || verified.Jkt != entry.OwnerKeyThumbprint)
        {
            return AAuth.Server.AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound);
        }
        return await entry.Lifecycle.ExecuteAsync(ctx, entry.ExpiresAt, TimeProvider.System, async () =>
        {
            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                entry.Lifecycle.Cancel();
                return Results.NoContent();
            }
            var reference = entry.Permission?.MissionS256 ?? entry.Interaction?.MissionS256;
            var mission = reference is null ? null : await missions.GetAsync(reference, ctx.RequestAborted);
            if (GovernanceEndpoints.Authorize(ctx, reference, mission) is { } denied) return denied;
            return await CompletePendingAsync(ctx, entry, options, missions, log);
        });
    }

    private static async Task<IResult> CompletePendingAsync(HttpContext ctx, DeferredConsent entry,
        AAuthGovernancePipelineOptions options, IMissionStore missions, IMissionLog log)
    {

        // Hold at 202 until the user decides on the PS consent page.
        if (entry.Decision is null)
        {
            return DeferredAccepted(ctx, options, entry);
        }

        if (entry.Kind == DeferredConsentKind.MissionCreation)
        {
            if (!entry.Decision.Value)
            {
                ctx.Response.Headers.CacheControl = "no-store";
                return AAuth.Server.AAuthProblemDetails.Create("denied", "the user declined this mission", statusCode: StatusCodes.Status403Forbidden);
            }
            var proposal = entry.Proposal!;
            return await CompleteMissionAsync(
                ctx, missions, entry.PersonServer, entry.Agent, proposal, proposal.Tools, entry.MissionExpiresAt).ConfigureAwait(false);
        }

        if (entry.Kind == DeferredConsentKind.Interaction)
        {
            if (!entry.Decision.Value)
                return AAuth.Server.AAuthProblemDetails.Create("denied", statusCode: StatusCodes.Status403Forbidden);
            // The user completed the relayed interaction / payment; the poll loop
            // terminates with the relay's final response (§Interaction Response).
            // The interaction was already recorded in the mission log when it was
            // relayed, so no further bookkeeping is needed here.
            return Results.Json(new { status = "ok" });
        }

        if (entry.Kind == DeferredConsentKind.Completion)
        {
            // The user finished reviewing the completion summary (§Interaction
            // Response). Accept → terminate the mission; follow-up/decline → the
            // mission stays active.
            var accepted = entry.Decision.Value;
            var completionMission = entry.Interaction?.MissionS256;
            if (accepted && completionMission is not null)
            {
                await missions.SetStateAsync(completionMission, MissionState.Terminated).ConfigureAwait(false);
                return Results.Json(new { mission_status = "terminated" });
            }
            return Results.Json(new { mission_status = "active" });
        }

        // Permission: the endpoint always returns a decision (200), never a denial.
        var request = entry.Permission!;
        var granted = entry.Decision.Value;
        if (request.MissionS256 is not null)
        {
            await log.AppendAsync(new MissionLogEntry(
                request.MissionS256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
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

    // Build the verbatim mission blob, persist the mission, and answer with the
    // §Mission Approval response { s256, mission, person_tokens? }.
    private static async Task<IResult> CompleteMissionAsync(
        HttpContext ctx,
        IMissionStore missions,
        string personServer,
        string agent,
        MissionProposal proposal,
        IReadOnlyList<MissionTool> approvedTools,
        DateTimeOffset? expiresAt = null)
    {
        var (blob, s256) = MissionApprovalBuilder.Build(
            agent, proposal, approvedTools, DateTimeOffset.UtcNow, expiresAt, proposal.Resources);
        await missions.SaveAsync(new StoredMission(s256, personServer, agent, blob) { ExpiresAt = expiresAt }).ConfigureAwait(false);
        IReadOnlyDictionary<string, string>? personTokens = null;
        if (proposal.Resources.Count > 0
            && ctx.RequestServices.GetService<IMissionPersonTokenIssuer>() is { } issuer
            && PersonTokenRequest(ctx, personServer, agent, s256, expiresAt, proposal.Resources) is { } request)
        {
            personTokens = await issuer.IssueAsync(request, ctx.RequestAborted).ConfigureAwait(false);
        }
        return Results.Json(MissionApprovalBuilder.Response(blob, s256, personTokens: personTokens));
    }

    // The verified agent token that signed this request (the proposal, or the poll
    // of its parked approval, which the owner check binds to the same agent key).
    // A sub-agent obtains person tokens only through its parent (§Sub-Agents).
    private static MissionPersonTokenRequest? PersonTokenRequest(HttpContext ctx, string personServer, string agent,
        string s256, DateTimeOffset? expiresAt, IReadOnlyList<string> resources)
    {
        if (ctx.GetAAuthVerification() is not { TokenType: AAuthTokenType.AgentToken, IssuerVerified: true }
            || ctx.GetAAuthParsedKey()?.Payload is not { } payload
            || payload["parent_agent"] is not null
            || payload["cnf"]?["jwk"] is not JsonObject jwk)
        {
            return null;
        }
        AAuth.Server.TokenRegistration registration;
        try { registration = AAuth.Server.TokenRegistration.FromPayload(payload); }
        catch (AAuth.Tokens.TokenVerificationException) { return null; }
        return new MissionPersonTokenRequest
        {
            PersonServer = personServer,
            AgentId = agent,
            ConfirmationKey = AAuth.Crypto.KeyFactory.FromPublicJwk(jwk),
            AgentTokenExpiresAt = registration.ExpiresAt,
            SourceTokens = [registration],
            MissionS256 = s256,
            MissionExpiresAt = expiresAt,
            Resources = resources,
        };
    }

    // POST {mission_endpoint}/{mission_s256}: `update` (§Mission Update) or
    // `completion` (§Mission Completion) of a mission the signing agent owns.
    private static async Task<IResult> HandleMissionActionAsync(
        HttpContext ctx,
        string missionS256,
        AAuthGovernancePipelineOptions options,
        IMissionStore missions,
        IMissionLog log,
        IInteractionRelay relay)
    {
        var body = await ReadJsonAsync(ctx).ConfigureAwait(false);
        var action = (string?)(body?["action"] as JsonValue);
        if (body is null || !AAuth.Tokens.MissionReference.IsValid(missionS256) || action is not ("update" or "completion"))
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
        var stored = await missions.GetAsync(missionS256).ConfigureAwait(false);
        if (GovernanceEndpoints.Authorize(ctx, missionS256, stored) is { } denied) return denied;

        if (action == "update")
        {
            var description = (string?)(body["description"] as JsonValue);
            if (string.IsNullOrWhiteSpace(description))
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "update requires a description", statusCode: StatusCodes.Status400BadRequest);
            // The s256 covers the update's bytes exactly as the PS persists them.
            var persisted = new JsonObject { ["description"] = description, ["accepted_at"] = DateTimeOffset.UtcNow.ToString("o") }.ToJsonString();
            var updateS256 = Mission.ComputeS256(System.Text.Encoding.UTF8.GetBytes(persisted));
            await log.AppendAsync(new MissionLogEntry(missionS256, MissionLogEntryKind.Update, DateTimeOffset.UtcNow)
            {
                Detail = persisted,
            }).ConfigureAwait(false);
            return Results.Json(new { s256 = updateS256 });
        }

        var summary = (string?)(body["summary"] as JsonValue);
        if (string.IsNullOrWhiteSpace(summary))
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "completion requires a summary", statusCode: StatusCodes.Status400BadRequest);
        var request = new InteractionRequest(InteractionType.Completion) { Summary = summary, MissionS256 = missionS256 };
        var result = await relay.RelayAsync(request, ctx.RequestAborted).ConfigureAwait(false);
        await log.AppendAsync(new MissionLogEntry(missionS256, MissionLogEntryKind.Interaction, DateTimeOffset.UtcNow)
        {
            Detail = request.Type.ToString(),
        }).ConfigureAwait(false);
        // The PS returns a deferred response while the person reviews the summary.
        if (result.Pending && ctx.RequestServices.GetService<IDeferredConsentStore>() is { } completionStore)
        {
            var verification = ctx.GetAAuthVerification()!;
            var parkedCompletion = await completionStore.ParkAsync(new DeferredConsent
            {
                Kind = DeferredConsentKind.Completion,
                Agent = verification.Agent!,
                OwnerIssuer = verification.Issuer,
                OwnerKeyThumbprint = verification.Jkt,
                PersonServer = ResolvePersonServer(ctx, options),
                Interaction = request,
            }, ctx.RequestAborted).ConfigureAwait(false);
            return DeferredAccepted(ctx, options, parkedCompletion);
        }
        if (result.Accepted == true)
        {
            await missions.SetStateAsync(missionS256, MissionState.Terminated).ConfigureAwait(false);
            return Results.Json(new { mission_status = "terminated" });
        }
        return Results.Json(new { mission_status = "active" });
    }

    // Emit a 202 Accepted with a poll Location (and, when configured, an
    // interaction requirement header) for a parked deferred consent.
    private static IResult DeferredAccepted(
        HttpContext ctx, AAuthGovernancePipelineOptions options, DeferredConsent pending)
    {
        var pollPath = options.Resolve(options.PendingPath).TrimEnd('/') + "/" + pending.Id;
        ctx.Response.Headers.Location = pollPath;
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers.CacheControl = "no-store";
        if (!string.IsNullOrEmpty(options.InteractionUrl))
        {
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format(options.InteractionUrl, pending.Code, options.EgressPolicy);
        }
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // The PS identifier: the configured PersonServer, else the request origin.
    private static string ResolvePersonServer(HttpContext ctx, AAuthGovernancePipelineOptions options)
        => string.IsNullOrEmpty(options.PersonServer)
            ? $"{ctx.Request.Scheme}://{ctx.Request.Host}"
            : options.PersonServer;

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
