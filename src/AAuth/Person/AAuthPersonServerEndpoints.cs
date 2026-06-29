using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server.Governance;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AAuth.Person;

/// <summary>
/// Configuration for <see cref="AAuthPersonServerEndpoints.MapAAuthPersonServer"/>.
/// </summary>
public sealed class AAuthPersonServerOptions
{
    /// <summary>HTTPS URL of this Person Server (<c>iss</c> of minted auth tokens).</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The PS signing keys, keyed by <c>kid</c>. Published at the JWKS and used
    /// to sign minted auth tokens (the first entry signs).
    /// </summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>The token endpoint path. Default <c>/token</c>.</summary>
    public string TokenPath { get; init; } = "/token";

    /// <summary>The pending (poll) path prefix. Default <c>/pending</c>.</summary>
    public string PendingPathPrefix { get; init; } = "/pending";

    /// <summary>
    /// The fallback scope when the resource token carries none. Default empty:
    /// the spec makes <c>scope</c> OPTIONAL, so a scopeless resource token mints
    /// a scopeless auth token (still valid via its <c>sub</c>) rather than
    /// injecting an arbitrary scope.
    /// </summary>
    public string DefaultScope { get; init; } = "";

    /// <summary>
    /// The PS-hosted interaction/consent path advertised on
    /// <c>requirement=interaction</c>. Default <c>/interaction</c>. The caller
    /// maps this endpoint and resolves the verdict against the shared
    /// <see cref="IPersonPendingStore"/>.
    /// </summary>
    public string InteractionPath { get; init; } = "/interaction";

    /// <summary>
    /// Access Server allow-list for four-party federation. <b>Open by default
    /// (spec-compliant):</b> when <c>null</c>, the PS federates to the AS named in
    /// a <em>verified</em> resource token's <c>aud</c> — §PS-AS Trust Establishment
    /// requires no separate registration step. An <b>empty</b> set disables the
    /// four-party branch (three-party only). A non-empty set restricts to the listed
    /// Access Servers. Composed by AND with <see cref="IsTrustedAccessServer"/>.
    /// </summary>
    public IReadOnlyCollection<string>? TrustedAccessServers { get; init; }

    /// <summary>
    /// Optional trust policy for Access Servers, evaluated per resource-token
    /// <c>aud</c> before the PS→AS federation call and composed by AND with
    /// <see cref="TrustedAccessServers"/>. <c>null</c> ⇒ no policy constraint.
    /// Assign <see cref="AAuth.Server.AAuthTrust.Any"/> to state intentional open
    /// federation explicitly.
    /// </summary>
    public Func<string, bool>? IsTrustedAccessServer { get; init; }

    /// <summary>
    /// The §Interaction Endpoint URL advertised in the PS metadata
    /// (<c>interaction_endpoint</c>), where agents POST mission interaction /
    /// payment / question / completion requests. Distinct from
    /// <see cref="InteractionPath"/> (the consent URL on <c>requirement=interaction</c>).
    /// When null the metadata falls back to <see cref="InteractionPath"/>.
    /// </summary>
    public string? InteractionEndpoint { get; init; }

    /// <summary>The mission endpoint URL advertised in the PS metadata (<c>mission_endpoint</c>), if any.</summary>
    public string? MissionEndpoint { get; init; }

    /// <summary>The permission endpoint URL advertised in the PS metadata (<c>permission_endpoint</c>), if any.</summary>
    public string? PermissionEndpoint { get; init; }

    /// <summary>The audit endpoint URL advertised in the PS metadata (<c>audit_endpoint</c>), if any.</summary>
    public string? AuditEndpoint { get; init; }

    /// <summary>
    /// Additional path prefixes the mapper's request-signature verification skips,
    /// on top of <c>/.well-known</c> and the interaction path. A PS uses this to
    /// declare its own unsigned surfaces — e.g. a browser consent/admin page that
    /// records the user's decision (§PS Approval Endpoint Authentication: how the
    /// PS authenticates the approving party is out of scope, so these stay the
    /// PS's own). Prefixes are matched with <c>StartsWithSegments</c>.
    /// </summary>
    public IReadOnlyCollection<string>? UnsignedPathPrefixes { get; init; }
}

/// <summary>
/// Maps the Person Server token endpoint, pending poll endpoint, and well-known
/// metadata in one call — the three-/four-party counterpart to
/// <c>MapAAuthAccessServer</c>. The AAuth crypto (signature verification,
/// resource-token verification, the auth-token mint, the §Auth Token Delivery
/// check, and PS→AS federation) lives here; only the identity + consent
/// decision is delegated to the DI-registered
/// <see cref="IIdentityClaimsAsserter"/>. When a request carries a mission
/// claim, the host packages the mission three-gate model (terminated rejection,
/// prior-consent silent grant, and park-and-prompt) over the
/// <see cref="IMissionStore"/>/<see cref="IMissionLog"/> primitives.
/// </summary>
public static class AAuthPersonServerEndpoints
{
    /// <summary>
    /// Configure the PS pipeline: publish <c>/.well-known/aauth-person.json</c>
    /// + JWKS, add the request-signature verification middleware (excluding the
    /// well-known and interaction paths), and map the token + pending endpoints.
    /// Resolves <see cref="TokenVerifier"/>, <see cref="MetadataClient"/>,
    /// <see cref="JwksClient"/>, <see cref="IIdentityClaimsAsserter"/>, and
    /// <see cref="IPersonPendingStore"/> from DI. The mission gate additionally
    /// resolves <see cref="IMissionStore"/> and <see cref="IMissionLog"/>;
    /// call-chaining resolves <see cref="UpstreamTokenValidator"/>; the
    /// four-party branch resolves <see cref="AccessServerClient"/>.
    /// </summary>
    public static WebApplication MapAAuthPersonServer(
        this WebApplication app,
        AAuthPersonServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        if (options.SigningKeys.Count == 0)
        {
            throw new InvalidOperationException("AAuthPersonServerOptions.SigningKeys must contain at least one key.");
        }

        // Fail fast on misconfigured spec-constrained URLs/paths: the issuer is the
        // token `iss`/`aud` anchor (MUST be absolute https), the interaction path is
        // appended with `?code=…` (so it carries no query/fragment), and each trusted
        // Access Server is a four-party anchor (MUST be absolute https).
        if (!AAuth.AAuthUrl.IsHttpsOrLoopback(options.Issuer))
        {
            throw new InvalidOperationException(
                "AAuthPersonServerOptions.Issuer must be an absolute https URL (loopback http allowed for development).");
        }
        if (options.InteractionPath is { } interactionPathRaw
            && (interactionPathRaw.Contains('?') || interactionPathRaw.Contains('#')))
        {
            throw new InvalidOperationException(
                "AAuthPersonServerOptions.InteractionPath must not contain a query or fragment.");
        }
        foreach (var trustedAs in options.TrustedAccessServers ?? Array.Empty<string>())
        {
            if (!AAuth.AAuthUrl.IsHttpsOrLoopback(trustedAs))
            {
                throw new InvalidOperationException(
                    $"AAuthPersonServerOptions.TrustedAccessServers entry '{trustedAs}' must be an absolute https URL " +
                    "(loopback http allowed for development).");
            }
        }

        string signingKid = string.Empty;
        AAuthKey signingKey = null!;
        foreach (var (kid, key) in options.SigningKeys)
        {
            signingKid = kid;
            signingKey = key;
            break;
        }

        var issuer = options.Issuer.TrimEnd('/');
        var interactionPath = "/" + options.InteractionPath.Trim('/');
        var interactionPrefix = interactionPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : interactionPath;
        var interactionUrl = $"{issuer}{interactionPath}";

        var trustedAccessServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var asUrl in options.TrustedAccessServers ?? Array.Empty<string>())
        {
            trustedAccessServers.Add(asUrl.TrimEnd('/'));
        }

        // Preserve null (open: federate to the AS named in a verified resource
        // token's aud) vs. empty (three-party only). The materialized set drives
        // membership; the nullable form drives the open/empty distinction.
        IReadOnlyCollection<string>? trustedAccessServersOrNull =
            options.TrustedAccessServers is null ? null : trustedAccessServers;

        var unsignedPrefixes = (options.UnsignedPathPrefixes ?? Array.Empty<string>())
            .Select(p => "/" + p.Trim('/'))
            .Where(p => p.Length > 1)
            .ToArray();

        // 1. Well-known metadata + JWKS (reachable without a signature).
        WellKnownEndpoints.MapAAuthPersonServerWellKnown(app, new AAuthPersonServerMetadataOptions
        {
            Issuer = options.Issuer,
            TokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = new Dictionary<string, AAuthKey>(options.SigningKeys),
            InteractionEndpoint = options.InteractionEndpoint ?? interactionUrl,
            MissionEndpoint = options.MissionEndpoint,
            PermissionEndpoint = options.PermissionEndpoint,
            AuditEndpoint = options.AuditEndpoint,
        });

        // 2. Verification middleware. The agent signs with the jwt scheme
        //    (RequireIssuerVerification=false); the browser-facing interaction
        //    endpoint carries no signature, so exclude it — plus any unsigned
        //    surfaces the PS declares (e.g. its own consent/admin page).
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix)
                && !unsignedPrefixes.Any(p => ctx.Request.Path.StartsWithSegments(p)),
            branch => branch.UseAAuthVerification(AAuthVerificationOptions.SignatureOnly()));

        var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var asserter = app.Services.GetRequiredService<IIdentityClaimsAsserter>();
        var pending = app.Services.GetRequiredService<IPersonPendingStore>();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.PersonServer");

        // Startup footgun guard (diagnostics only): warn when federation is open by
        // default. Suppressed by any explicit policy (including AAuthTrust.Any).
        TrustConfigDiagnostics.WarnIfOpenFederation(
            logger,
            trustConfigured: options.TrustedAccessServers is not null || options.IsTrustedAccessServer is not null,
            "MapAAuthPersonServer",
            "this Person Server federates to any Access Server named in a verified resource token's aud " +
            "because no TrustedAccessServers / IsTrustedAccessServer policy is configured (the AAuth spec " +
            "default). Configure a policy to restrict, or assign AAuthTrust.Any to declare intentional open " +
            "federation and silence this warning.");

        string MintEntry(PersonPendingEntry entry) => Mint(
            entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey!,
            entry.Subject ?? "pairwise-sub", entry.Tenant, entry.Roles, entry.Groups,
            entry.AdditionalClaims, entry.UpstreamAct, entry.Mission);

        string Mint(
            string resourceUrl, string agentId, string scope, IAAuthKey confirmationKey,
            string subject, string? tenant, IReadOnlyList<string>? roles, IReadOnlyList<string>? groups,
            IReadOnlyDictionary<string, JsonNode?>? additionalClaims, JsonObject? upstreamAct, MissionClaim? mission) =>
            new AuthTokenBuilder
            {
                Issuer = options.Issuer,
                Audience = resourceUrl,
                Agent = agentId,
                AgentConfirmationKey = confirmationKey,
                Key = signingKey,
                KeyId = signingKid,
                Subject = subject,
                Scope = scope,
                Tenant = tenant,
                Roles = roles,
                Groups = groups,
                AdditionalClaims = additionalClaims,
                Act = upstreamAct,
                Mission = mission,
            }.Build();

        // -------------------------------------------------------------------
        // POST {TokenPath} — the PS token endpoint (§Agent Token Request).
        // -------------------------------------------------------------------
        app.MapPost(options.TokenPath, async (HttpContext ctx) =>
        {
            var parsed = ctx.GetAAuthParsedKey()!;

            // Only an agent token may exchange — a signature-verified carrier of
            // the wrong type is an authorization refusal (403), not a 401
            // signature failure (§Error Responses reserves 401 + Signature-Error
            // for the §Verification steps, which already passed).
            if (ctx.GetAAuthTokenType() != AAuthTokenType.AgentToken)
            {
                return Results.Json(
                    new { error = "invalid_carrier_token", detail = $"expected {AAuthConstants.TokenTypes.AgentToken}, got {ctx.GetAAuthTokenType()}" },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            var agentId = (string?)parsed.Payload?["sub"];
            if (string.IsNullOrEmpty(agentId))
            {
                return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            JsonObject? body;
            try
            {
                body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
            }
            catch (System.Text.Json.JsonException)
            {
                return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceTokenJwt = (string?)body?["resource_token"];
            if (string.IsNullOrEmpty(resourceTokenJwt))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing resource_token" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var upstreamTokenJwt = (string?)body?["upstream_token"];
            var subagentTokenJwt = (string?)body?["subagent_token"];

            // §Agent Token Request: optional consent-shaping params. `prompt` is an
            // OIDC string; `capabilities` is the request-body equivalent of the
            // AAuth-Capabilities header. Both are tolerant — unknown values flow to
            // the asserter, which MAY honor or ignore them.
            var prompt = (string?)body?["prompt"];
            var capabilities = ParseStringArray(body?["capabilities"] as JsonArray);

            // §Single-Level Depth: a PS MUST reject a token request signed by an
            // agent whose own token carries `parent_agent` — a sub-agent cannot
            // request authorization on its own behalf; its parent must mediate.
            if (parsed.Payload?["parent_agent"] is not null)
            {
                return Results.Json(
                    new { error = "invalid_request", detail = "a sub-agent MUST NOT request authorization directly; the parent mediates (§Sub-Agents)" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Route on the resource token's `aud` (peeked, not trusted; both
            // branches fully verify the token afterwards). `aud == this PS` →
            // three-party collapsed mint; `aud == an AS` → four-party federation.
            var resourceAudience = PeekJwtAudience(resourceTokenJwt);
            if (resourceAudience is not null
                && !string.Equals(resourceAudience.TrimEnd('/'), issuer, StringComparison.OrdinalIgnoreCase))
            {
                return await HandleFederatedAsync(
                    ctx, parsed, agentId, resourceTokenJwt, upstreamTokenJwt, resourceAudience);
            }

            return await HandleThreePartyAsync(
                ctx, parsed, agentId, resourceTokenJwt, upstreamTokenJwt, subagentTokenJwt, prompt, capabilities);
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the agent polls the deferred verdict.
        // -------------------------------------------------------------------
        app.MapGet($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return Results.NotFound(new { error = "unknown_interaction" });
            }

            // Mission-gate entries resolve through the consent seam + the
            // clarification protocol (§Agent Token Request gate 2c).
            if (entry.MissionGate)
            {
                return await ResolveMissionGateAsync(ctx, entry);
            }

            // Four-party entries resolve via the background federation task.
            if (entry.AgentConfirmationKey is null)
            {
                if (entry.Status == PersonPendingStatus.Allowed && entry.AuthToken is not null)
                {
                    return Results.Ok(new { auth_token = entry.AuthToken });
                }
                if (entry.Status == PersonPendingStatus.Denied)
                {
                    if (!string.IsNullOrEmpty(entry.ErrorLocation))
                    {
                        ctx.Response.Headers.Location = entry.ErrorLocation;
                    }
                    return Results.Json(
                        new { error = entry.Error ?? "denied" },
                        statusCode: entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
                }
                return Pending202(ctx, entry, options, interactionUrl);
            }

            // Three-party entries resolve when the host's interaction page marks
            // the verdict against the shared store.
            switch (entry.Status)
            {
                case PersonPendingStatus.Allowed:
                    return Results.Ok(new { auth_token = MintEntry(entry) });
                case PersonPendingStatus.Denied:
                    return Results.Json(
                        new { error = "denied", detail = entry.DenyReason },
                        statusCode: StatusCodes.Status403Forbidden);
                case PersonPendingStatus.Pending:
                default:
                    return Pending202(ctx, entry, options, interactionUrl);
            }
        });

        // POST {PendingPathPrefix}/{id} — the agent answers a clarification
        // (§Agent Response to Clarification) or replaces its request. The SDK
        // records it in the mission log and readies the next review.
        app.MapPost($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            // 404 (not 403) on a missing entry or a mismatched requester so the
            // endpoint never confirms another agent's pending id exists.
            if (entry is null || !entry.MissionGate || !RequesterMatches(ctx, entry))
            {
                return Results.NotFound(new { error = "unknown_interaction" });
            }
            if (entry.Status == PersonPendingStatus.Withdrawn)
            {
                return Results.Json(new { error = "request_withdrawn" }, statusCode: StatusCodes.Status410Gone);
            }

            JsonObject? body;
            try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
            catch (System.Text.Json.JsonException)
            {
                return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
            }

            // §Agent Response to Clarification: the body MUST carry a
            // clarification_response or a replacement resource_token.
            var answer = (string?)body?["clarification_response"];
            var updatedResourceToken = (string?)body?["resource_token"];
            if (answer is null && string.IsNullOrEmpty(updatedResourceToken))
            {
                return Results.Json(
                    new { error = "invalid_request", detail = "expected clarification_response or resource_token" },
                    statusCode: StatusCodes.Status400BadRequest);
            }
            if (answer is not null)
            {
                entry.ClarificationAnswers.Add(answer);
            }
            var missionLog = app.Services.GetRequiredService<IMissionLog>();
            await missionLog.AppendAsync(new MissionLogEntry(
                entry.Mission!.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
            {
                Detail = answer ?? "updated_request",
            });
            // The clarification round is answered — re-review on the next poll.
            entry.ClarificationQuestion = null;
            entry.Status = PersonPendingStatus.Pending;
            return Results.NoContent();
        });

        // DELETE {PendingPathPrefix}/{id} — the agent withdraws the request
        // (§Agent Response to Clarification — cancel). A later poll returns 410.
        app.MapDelete($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null || !entry.MissionGate || !RequesterMatches(ctx, entry))
            {
                return Results.NotFound(new { error = "unknown_interaction" });
            }
            entry.Status = PersonPendingStatus.Withdrawn;
            var missionLog = app.Services.GetRequiredService<IMissionLog>();
            await missionLog.AppendAsync(new MissionLogEntry(
                entry.Mission!.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
            {
                Detail = "cancelled",
            });
            return Results.NoContent();
        });

        return app;

        // ---- mission-gate resolution (gate 2c) -----------------------------
        async Task<IResult> ResolveMissionGateAsync(HttpContext ctx, PersonPendingEntry entry)
        {
            var missionLog = app.Services.GetRequiredService<IMissionLog>();
            var consent = app.Services.GetRequiredService<IMissionTokenConsent>();
            var s256 = entry.Mission!.S256;

            switch (entry.Status)
            {
                case PersonPendingStatus.Withdrawn:
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return Results.Json(new { error = "request_withdrawn" }, statusCode: StatusCodes.Status410Gone);

                case PersonPendingStatus.AwaitingClarification:
                    return Pending202Clarification(ctx, entry, options);

                case PersonPendingStatus.Allowed:
                    // Resolved out-of-band by the PS's user channel (MarkAllowed).
                    if (!entry.MissionResolved)
                    {
                        await AppendMissionTokenAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, "OutOfScope");
                        entry.MissionResolved = true;
                    }
                    return Results.Ok(new { auth_token = MintEntry(entry) });

                case PersonPendingStatus.Denied:
                    if (!entry.MissionResolved)
                    {
                        await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope);
                        entry.MissionResolved = true;
                    }
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return Results.Json(new { error = "denied", detail = entry.DenyReason },
                        statusCode: StatusCodes.Status403Forbidden);

                case PersonPendingStatus.Pending:
                default:
                    var decision = await consent.ReviewAsync(new MissionTokenConsentContext
                    {
                        AgentId = entry.AgentId,
                        ResourceUrl = entry.ResourceUrl,
                        Scope = entry.Scope,
                        Mission = entry.Mission!,
                        Stage = MissionTokenConsentStage.Resolve,
                        Prompt = entry.Prompt,
                        Capabilities = entry.Capabilities,
                        ClarificationHistory = entry.ClarificationAnswers,
                    });
                    switch (decision.Kind)
                    {
                        case MissionTokenConsentKind.Grant:
                            await AppendMissionTokenAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, "OutOfScope");
                            entry.MissionResolved = true;
                            return await ResolveMissionGrantAsync(entry);
                        case MissionTokenConsentKind.Deny:
                            await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope);
                            entry.MissionResolved = true;
                            entry.Status = PersonPendingStatus.Denied;
                            entry.DenyReason = decision.Reason ?? "the user denied this request";
                            ctx.Response.Headers["Cache-Control"] = "no-store";
                            return Results.Json(new { error = "denied", detail = entry.DenyReason },
                                statusCode: StatusCodes.Status403Forbidden);
                        case MissionTokenConsentKind.Clarify:
                            entry.Status = PersonPendingStatus.AwaitingClarification;
                            entry.ClarificationQuestion = decision.Question;
                            entry.ClarificationTimeout = decision.Timeout;
                            entry.ClarificationOptions = decision.Options;
                            return Pending202Clarification(ctx, entry, options);
                        case MissionTokenConsentKind.Interact:
                        default:
                            return Pending202(ctx, entry, options, interactionUrl);
                    }
            }
        }

        // Mint an out-of-scope grant: the asserter supplies identity, the verdict
        // is cached on the entry so a repeat poll is idempotent.
        async Task<IResult> ResolveMissionGrantAsync(PersonPendingEntry entry)
        {
            var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = entry.ResourceUrl,
                Scope = entry.Scope,
                AgentId = entry.AgentId,
                Mission = entry.Mission,
                Prompt = entry.Prompt,
                Capabilities = entry.Capabilities,
            });
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                entry.Status = PersonPendingStatus.Denied;
                entry.DenyReason = asserted.Reason ?? "identity assertion failed";
                return Results.Json(new { error = "denied", detail = entry.DenyReason },
                    statusCode: StatusCodes.Status403Forbidden);
            }
            entry.Subject = asserted.Subject;
            entry.Tenant = asserted.Tenant;
            entry.Roles = asserted.Roles;
            entry.Groups = asserted.Groups;
            entry.AdditionalClaims = asserted.AdditionalClaims;
            entry.Status = PersonPendingStatus.Allowed;
            return Results.Ok(new { auth_token = MintEntry(entry) });
        }

        // Silent grant (gate 2a / 2b): the asserter supplies identity, the SDK
        // mints immediately without parking.
        async Task<IResult> MintMissionGrantAsync(
            string audience, string boundAgentId, string scope, IAAuthKey confirmationKey,
            JsonObject? upstreamAct, MissionClaim mission, string? prompt,
            IReadOnlyList<string>? capabilities, string agentId)
        {
            var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = audience,
                Scope = scope,
                AgentId = agentId,
                Mission = mission,
                Prompt = prompt,
                Capabilities = capabilities,
            });
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                return Results.Json(new { error = "denied", detail = asserted.Reason },
                    statusCode: StatusCodes.Status403Forbidden);
            }
            return Results.Ok(new
            {
                auth_token = Mint(
                    audience, boundAgentId, scope, confirmationKey,
                    asserted.Subject ?? "pairwise-sub", asserted.Tenant, asserted.Roles,
                    asserted.Groups, asserted.AdditionalClaims, upstreamAct, mission),
            });
        }

        // ---- three-party (PS-asserted) handler -----------------------------
        async Task<IResult> HandleThreePartyAsync(
            HttpContext ctx, SignatureKeyParser.ParsedSignatureKeyInfo parsed,
            string agentId, string resourceTokenJwt, string? upstreamTokenJwt, string? subagentTokenJwt,
            string? prompt = null, IReadOnlyList<string>? capabilities = null)
        {
            // Call-chaining: validate upstream_token (§Upstream Token Verification).
            JsonObject? upstreamAct = null;
            if (!string.IsNullOrEmpty(upstreamTokenJwt))
            {
                var validator = app.Services.GetRequiredService<UpstreamTokenValidator>();
                var intermediaryResourceUrl = (string?)parsed.Payload?["iss"]
                    ?? throw new InvalidOperationException("Agent token missing 'iss' claim.");
                // §Upstream Token Verification step 2 (L1742): trust an upstream
                // issuer only when the PS "previously brokered" it (self) or is
                // "authorized to extend" it — explicitly: it is in the configured
                // TrustedAccessServers set or accepted by IsTrustedAccessServer.
                // Unlike first-hop federation (#4, open by default — L1581), four-party
                // CALL-CHAINING extension is a tighter, explicit decision (higher
                // delegation stakes): an unconfigured PS trusts only its own
                // (three-party) upstreams.
                Func<string, bool> isTrustedUpstreamIssuer = upstreamIss =>
                {
                    var normalized = upstreamIss.TrimEnd('/');
                    return string.Equals(normalized, issuer, StringComparison.OrdinalIgnoreCase)
                        || trustedAccessServers.Contains(normalized)
                        || (options.IsTrustedAccessServer?.Invoke(normalized) ?? false);
                };

                var result = await validator.ValidateAsync(
                    upstreamTokenJwt,
                    expectedAudience: intermediaryResourceUrl,
                    isTrustedUpstreamIssuer);
                if (!result.IsValid)
                {
                    return Results.Json(new { error = "invalid_upstream_token", detail = result.Error },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                // Four-party PS mission gate (§Call Chaining, draft-08 L1765): a PS
                // MUST require a mission to remain in the loop for four-party upstream
                // chains. The upstream token's `dwk` authoritatively identifies its
                // issuer (resolved and signature-verified during validation above):
                // `aauth-access.json` ⇒ an AS (four-party), `aauth-person.json` ⇒ a PS
                // (three-party). When a four-party upstream carries no mission, no
                // `mission.approver` anchors the chain to any PS — the intermediary
                // should have routed to its AS, not here — so reject. A three-party
                // upstream (PS-issued) without a mission stays allowed.
                if (result.MissionApprover is null
                    && string.Equals(result.IssuerDwk, AuthTokenBuilder.AccessDwk, StringComparison.Ordinal))
                {
                    return Results.Json(
                        new { error = "invalid_request", detail = "call chaining from a four-party (AS-issued) upstream token requires a mission so the PS stays in the loop (§Call Chaining)" },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                // Compose the downstream act node (§Delegation Chain): act.agent is
                // the upstream token's agent (the delegator), nesting the upstream's
                // own chain as act.act. `upstreamAct` now holds this complete node.
                upstreamAct = ActChainBuilder.BuildNestedAct(result.Agent!, result.UpstreamAct);
            }

            // §Sub-Agents (parent-mediated authorization): when a subagent_token is
            // present the signing agent is the parent. Verify the sub-agent token,
            // confirm its parent_agent names the signer, and bind the issued auth
            // token to the SUB-AGENT's key/identity while recording the parent in
            // the act chain. Consent is still evaluated for the parent (the agentId).
            var boundAgentId = agentId;
            var boundConfirmationKey = parsed.ConfirmationKey!;
            var boundUpstreamAct = upstreamAct;
            string? subagentJkt = null;
            if (!string.IsNullOrEmpty(subagentTokenJwt))
            {
                string subagentId;
                AAuthKey subagentKey;
                string? subagentParent;
                try
                {
                    var verifiedSub = await tokenVerifier.VerifyWithJwksAsync(
                        subagentTokenJwt, metadataClient, jwksClient,
                        AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null);
                    subagentId = (string?)verifiedSub.Payload["sub"]
                        ?? throw new TokenVerificationException("subagent_token missing sub");
                    var subCnf = verifiedSub.Payload["cnf"]?["jwk"] as JsonObject
                        ?? throw new TokenVerificationException("subagent_token missing cnf.jwk");
                    subagentKey = AAuthKey.FromJwk(subCnf);
                    subagentParent = (string?)verifiedSub.Payload["parent_agent"]
                        ?? throw new TokenVerificationException("subagent_token missing parent_agent");
                }
                catch (TokenVerificationException ex)
                {
                    return Results.Json(new { error = "invalid_agent_token", detail = ex.Message },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                // The signing agent (parent) MUST be named by subagent_token.parent_agent.
                if (!string.Equals(subagentParent, agentId, StringComparison.Ordinal))
                {
                    return Results.Json(
                        new { error = "invalid_request", detail = "subagent_token.parent_agent does not name the signing agent (§Sub-Agents)" },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                boundAgentId = subagentId;
                boundConfirmationKey = subagentKey;
                subagentJkt = subagentKey.ComputeJwkThumbprint();
                // Sub-agent act (§Delegation Chain): act.agent = the parent (the
                // signer that mediates). When the parent presented an upstream_token,
                // `upstreamAct` already records the parent as its top node; otherwise
                // build a single-node act naming the parent.
                boundUpstreamAct = upstreamAct ?? ActChainBuilder.BuildNestedAct(agentId);
            }

            // Verify the resource token (§Resource Token Verification). `iss`
            // becomes the auth token's `aud`; `scope` is echoed; `mission` (if
            // present) governs the request. For a sub-agent the resource token's
            // `agent`/`agent_jkt` bind to the sub-agent (step 6 uses subagentJkt).
            string audience;
            var requestedScope = options.DefaultScope;
            MissionClaim? missionClaim;
            try
            {
                var verified = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: options.Issuer,
                    expectedAgentId: boundAgentId,
                    expectedAgentJkt: parsed.ConfirmationKey!.ComputeJwkThumbprint(),
                    metadataClient, jwksClient,
                    expectedApprover: null,
                    subagentAgentJkt: subagentJkt);


                audience = (string?)verified.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                var scopeClaim = (string?)verified.Payload["scope"];
                if (!string.IsNullOrWhiteSpace(scopeClaim))
                {
                    requestedScope = scopeClaim;
                }
                missionClaim = MissionClaim.FromPayload(verified.Payload);
            }
            catch (TokenVerificationException ex)
            {
                var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
                // §Token Endpoint Error Codes: invalid_resource_token / expired_resource_token
                // are 400 (a bad token parameter in the body), not 401 — 401 is reserved for
                // request-signature failures carrying a Signature-Error header (§Authentication
                // Errors). The request itself was correctly signed; the resource_token is invalid.
                return Results.Json(
                    new { error = expired ? "expired_resource_token" : "invalid_resource_token", detail = ex.Message },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Mission gate (§Agent Token Request, three-gate model). The SDK owns
            // the gate structure + the clarification protocol; IMissionTokenConsent
            // owns the out-of-scope decision (L3226 "does not prescribe how the
            // decision is made"). Identity claims on a grant come from the asserter.
            if (missionClaim is not null)
            {
                var missionStore = app.Services.GetRequiredService<IMissionStore>();
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                var consent = app.Services.GetRequiredService<IMissionTokenConsent>();
                var s256 = missionClaim.S256;

                // Gate 1: a terminated mission is rejected outright.
                var stored = await missionStore.GetAsync(s256);
                if (stored is { State: MissionState.Terminated })
                {
                    return GovernanceEndpoints.MissionTerminated();
                }

                // Gate 2b: prior consent for this (resource, scope) → silent grant.
                if (await missionLog.HasPriorConsentAsync(s256, audience, requestedScope))
                {
                    await AppendMissionTokenAsync(missionLog, s256, audience, requestedScope, "PriorConsent");
                    return await MintMissionGrantAsync(
                        audience, boundAgentId, requestedScope, boundConfirmationKey,
                        boundUpstreamAct, missionClaim, prompt, capabilities, agentId);
                }

                // Gate 2a/2c: the consent seam decides in-scope-silent vs the
                // out-of-scope review (grant / deny / clarify / interactive hold).
                var decision = await consent.ReviewAsync(new MissionTokenConsentContext
                {
                    AgentId = agentId,
                    ResourceUrl = audience,
                    Scope = requestedScope,
                    Mission = missionClaim,
                    Stage = MissionTokenConsentStage.Gate,
                    Prompt = prompt,
                    Capabilities = capabilities,
                });
                switch (decision.Kind)
                {
                    case MissionTokenConsentKind.Grant:
                        // Gate 2a: within the approved intent → silent grant.
                        await AppendMissionTokenAsync(missionLog, s256, audience, requestedScope, "InScope");
                        return await MintMissionGrantAsync(
                            audience, boundAgentId, requestedScope, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities, agentId);
                    case MissionTokenConsentKind.Deny:
                        await AppendMissionTokenDenialAsync(missionLog, s256, audience, requestedScope);
                        return Results.Json(new { error = "denied", detail = decision.Reason },
                            statusCode: StatusCodes.Status403Forbidden);
                    case MissionTokenConsentKind.Clarify:
                        var clarifyEntry = ParkMissionGate(
                            pending, audience, requestedScope, boundAgentId, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities);
                        clarifyEntry.Status = PersonPendingStatus.AwaitingClarification;
                        clarifyEntry.ClarificationQuestion = decision.Question;
                        clarifyEntry.ClarificationTimeout = decision.Timeout;
                        clarifyEntry.ClarificationOptions = decision.Options;
                        return Pending202Clarification(ctx, clarifyEntry, options);
                    case MissionTokenConsentKind.Interact:
                    default:
                        var interactEntry = ParkMissionGate(
                            pending, audience, requestedScope, boundAgentId, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities);
                        return Pending202(ctx, interactEntry, options, interactionUrl);
                }
            }

            // Non-mission three-party path.
            var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = audience,
                Scope = requestedScope,
                AgentId = agentId,
                Prompt = prompt,
                Capabilities = capabilities,
            });
            switch (assertion.Kind)
            {
                case IdentityAssertionKind.Assert:
                    return Results.Ok(new
                    {
                        auth_token = Mint(
                            audience, boundAgentId, requestedScope, boundConfirmationKey,
                            assertion.Subject ?? "pairwise-sub", assertion.Tenant, assertion.Roles,
                            assertion.Groups, assertion.AdditionalClaims, boundUpstreamAct, mission: null),
                    });
                case IdentityAssertionKind.Deny:
                    return Results.Json(new { error = "denied", detail = assertion.Reason },
                        statusCode: StatusCodes.Status403Forbidden);
                case IdentityAssertionKind.NeedsConsent:
                default:
                    var entry = pending.Add(audience, requestedScope, boundAgentId, boundConfirmationKey, boundUpstreamAct);
                    return Pending202(ctx, entry, options, interactionUrl);
            }
        }

        // ---- four-party (federated) handler --------------------------------
        async Task<IResult> HandleFederatedAsync(
            HttpContext ctx, SignatureKeyParser.ParsedSignatureKeyInfo parsed,
            string agentId, string resourceTokenJwt, string? upstreamTokenJwt, string resourceAudience)
        {
            // §PS-AS Trust Establishment (L1581): trust may be pre-established OR
            // established dynamically — "no separate registration step". Default
            // open: federate to the AS named in the (verified) resource-token aud.
            // An empty TrustedAccessServers set disables four-party (three-party
            // only); a non-empty set and/or predicate restricts.
            if (!AAuthUrl.IsHttpsOrLoopback(resourceAudience))
            {
                return Results.Json(
                    new { error = "untrusted_access_server", detail = $"Access Server audience '{resourceAudience}' must be an absolute https URL (loopback http allowed for development)." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
            if (!IssuerTrust.IsTrusted(trustedAccessServersOrNull, options.IsTrustedAccessServer, resourceAudience.TrimEnd('/')))
            {
                return Results.Json(
                    new { error = "untrusted_access_server", detail = $"'{resourceAudience}' is not a trusted Access Server." },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            // Verify the resource token's agent binding before forwarding it.
            string resourceUrl;
            var federatedScope = options.DefaultScope;
            try
            {
                var verified = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: resourceAudience,
                    expectedAgentId: agentId,
                    expectedAgentJkt: parsed.ConfirmationKey!.ComputeJwkThumbprint(),
                    metadataClient, jwksClient);

                resourceUrl = (string?)verified.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                var scopeClaim = (string?)verified.Payload["scope"];
                if (!string.IsNullOrWhiteSpace(scopeClaim))
                {
                    federatedScope = scopeClaim;
                }
            }
            catch (TokenVerificationException ex)
            {
                var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
                // §Token Endpoint Error Codes: invalid_resource_token / expired_resource_token
                // are 400 (a bad token parameter in the body), not 401 — 401 is reserved for
                // request-signature failures carrying a Signature-Error header (§Authentication
                // Errors). The request itself was correctly signed; the resource_token is invalid.
                return Results.Json(
                    new { error = expired ? "expired_resource_token" : "invalid_resource_token", detail = ex.Message },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var federation = app.Services.GetRequiredService<AccessServerClient>();
            var entry = pending.Add(resourceUrl, federatedScope, agentId, agentConfirmationKey: null);

            var agentTokenJwt = parsed.Jwt
                ?? throw new InvalidOperationException("Agent token JWT unavailable on the verified request.");
            var agentConfirmationKey = parsed.ConfirmationKey!;
            var fedRequest = new AccessServerRequest
            {
                ResourceToken = resourceTokenJwt,
                AgentToken = agentTokenJwt,
                UpstreamToken = upstreamTokenJwt,
                ExpectedAudience = resourceUrl,
                ExpectedAgentId = agentId,
                AgentKey = agentConfirmationKey,
                RequestedScope = federatedScope,
                OnInteractionRequired = (interaction, _) =>
                {
                    entry.InteractionUrl = interaction.Url;
                    entry.InteractionCode = interaction.Code;
                    entry.FirstAnswer.TrySetResult();
                    return Task.CompletedTask;
                },
                // The AS needs identity claims (§Claims Required) for its policy
                // decision. The PS is the identity authority — answer via the
                // same asserter, mapping its Assert into the directed claims push.
                OnClaimsRequired = async (claimsRequirement, ct) =>
                {
                    var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
                    {
                        ResourceUrl = resourceUrl,
                        Scope = federatedScope,
                        AgentId = agentId,
                        RequiredClaims = claimsRequirement.RequiredClaims,
                    }, ct);
                    return new ClaimsResponse
                    {
                        Subject = asserted.Subject ?? "pairwise-sub",
                        Claims = ProjectClaims(asserted, claimsRequirement.RequiredClaims),
                    };
                },
            };

            _ = Task.Run(async () =>
            {
                try
                {
                    var token = await federation.FederateAsync(resourceAudience, fedRequest);
                    entry.AuthToken = token;
                    entry.Status = PersonPendingStatus.Allowed;
                }
                catch (AAuthInteractionDeniedException)
                {
                    entry.Error = "denied";
                    entry.ErrorStatus = StatusCodes.Status403Forbidden;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (AAuthTokenExchangeException ex)
                {
                    entry.Error = ex.ErrorCode;
                    entry.ErrorStatus = ex.StatusCode;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (AAuthPaymentRequiredException ex)
                {
                    entry.Error = "payment_required";
                    entry.ErrorStatus = StatusCodes.Status402PaymentRequired;
                    entry.ErrorLocation = ex.Location;
                    entry.Status = PersonPendingStatus.Denied;
                }
                catch (Exception ex)
                {
                    entry.Error = "federation_failed";
                    entry.ErrorStatus = StatusCodes.Status502BadGateway;
                    logger.LogWarning(ex, "Four-party federation to {AccessServer} failed.", resourceAudience);
                    entry.Status = PersonPendingStatus.Denied;
                }
                finally
                {
                    entry.FirstAnswer.TrySetResult();
                }
            });

            await entry.FirstAnswer.Task;

            if (entry.InteractionUrl is not null)
            {
                ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                ctx.Response.Headers["Retry-After"] = "1";
                ctx.Response.Headers["Cache-Control"] = "no-store";
                ctx.Response.Headers[AAuthRequirementHeader.Name] =
                    Interaction.Format(entry.InteractionUrl, entry.InteractionCode!);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }

            if (entry.Status == PersonPendingStatus.Allowed)
            {
                return Results.Ok(new { auth_token = entry.AuthToken });
            }

            if (!string.IsNullOrEmpty(entry.ErrorLocation))
            {
                ctx.Response.Headers.Location = entry.ErrorLocation;
            }
            return Results.Json(
                new { error = entry.Error ?? "denied" },
                statusCode: entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
        }
    }

    private static PersonPendingEntry ParkMissionGate(
        IPersonPendingStore pending, string audience, string scope, string agentId,
        IAAuthKey confirmationKey, JsonObject? upstreamAct, MissionClaim mission,
        string? prompt, IReadOnlyList<string>? capabilities)
    {
        var entry = pending.Add(audience, scope, agentId, confirmationKey, upstreamAct, mission);
        entry.MissionGate = true;
        entry.Prompt = prompt;
        entry.Capabilities = capabilities;
        return entry;
    }

    private static IResult Pending202(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options, string interactionUrl)
    {
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format(interactionUrl, entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // True when the verified carrier on this request is the agent that parked the
    // entry — guards the clarification POST/DELETE so one agent cannot answer or
    // withdraw another's pending request (the signature is already verified).
    private static bool RequesterMatches(HttpContext ctx, PersonPendingEntry entry)
    {
        var sub = (string?)ctx.GetAAuthParsedKey()?.Payload?["sub"];
        return sub is not null && string.Equals(sub, entry.AgentId, StringComparison.Ordinal);
    }

    // The §requirement-clarification 202: emit the AAuth-Requirement header and a
    // body carrying the question (plus optional timeout/options).
    private static IResult Pending202Clarification(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options)
    {
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            $"requirement={ClarificationRequirement.RequirementType}";
        var body = new JsonObject
        {
            ["status"] = "pending",
            ["clarification"] = entry.ClarificationQuestion,
        };
        if (entry.ClarificationTimeout is int timeout)
        {
            body["timeout"] = timeout;
        }
        if (entry.ClarificationOptions is { Count: > 0 } opts)
        {
            var array = new JsonArray();
            foreach (var option in opts)
            {
                array.Add(option);
            }
            body["options"] = array;
        }
        return Results.Json(body, statusCode: StatusCodes.Status202Accepted);
    }

    private static Task AppendMissionTokenDenialAsync(
        IMissionLog missionLog, string s256, string resource, string scope)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = false,
            Detail = "OutOfScope",
        });

    private static Task AppendMissionTokenAsync(
        IMissionLog missionLog, string s256, string resource, string scope, string detail)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = true,
            Detail = detail,
        });

    // Project the asserter's claims (tenant/roles/groups/additional) into the
    // §Claims Required push payload, limited to the names the AS requested.
    private static IReadOnlyDictionary<string, JsonNode?> ProjectClaims(
        IdentityAssertion asserted, IReadOnlyList<string> requiredClaims)
    {
        var result = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var name in requiredClaims)
        {
            switch (name)
            {
                case "tenant" when asserted.Tenant is not null:
                    result["tenant"] = asserted.Tenant;
                    break;
                case "roles" when asserted.Roles is not null:
                    result["roles"] = new JsonArray(System.Linq.Enumerable.ToArray(
                        System.Linq.Enumerable.Select(asserted.Roles, r => (JsonNode?)r)));
                    break;
                case "groups" when asserted.Groups is not null:
                    result["groups"] = new JsonArray(System.Linq.Enumerable.ToArray(
                        System.Linq.Enumerable.Select(asserted.Groups, g => (JsonNode?)g)));
                    break;
                default:
                    if (asserted.AdditionalClaims is not null
                        && asserted.AdditionalClaims.TryGetValue(name, out var value))
                    {
                        result[name] = value?.DeepClone();
                    }
                    break;
            }
        }
        return result;
    }

    // Peek the `aud` claim of a (possibly unverified) compact JWT without
    // checking its signature — used only to ROUTE the request (three- vs
    // four-party). Both branches fully verify the token afterwards.
    private static string? PeekJwtAudience(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }
        JsonObject? payload;
        try
        {
            payload = JsonNode.Parse(Base64UrlDecode(parts[1])) as JsonObject;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
        return payload?["aud"] switch
        {
            JsonValue v => v.GetValue<string>(),
            JsonArray { Count: > 0 } a => (string?)a[0],
            _ => null,
        };
    }

    private static string Base64UrlDecode(string segment)
    {
        var s = segment.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }

    // Parse a JSON array of strings (e.g. the `capabilities` body parameter) into
    // a list, skipping non-string entries. Returns null when absent/empty so the
    // asserter can distinguish "not declared" from "declared empty".
    private static IReadOnlyList<string>? ParseStringArray(JsonArray? array)
    {
        if (array is null || array.Count == 0)
        {
            return null;
        }
        var list = new List<string>(array.Count);
        foreach (var node in array)
        {
            if (node is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrEmpty(s))
            {
                list.Add(s);
            }
        }
        return list.Count > 0 ? list : null;
    }
}
