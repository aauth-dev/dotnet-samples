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
using AAuth.Server;
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
    public AAuthEgressPolicy EgressPolicy { get; init; } = AAuthEgressPolicy.Production;
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    public Func<PersonPendingEntry, ClarificationRequirement, System.Threading.CancellationToken, Task<ClarificationResponse?>>? TriageClarificationAsync { get; init; }

    /// <summary>HTTPS URL of this Person Server (<c>iss</c> of minted auth tokens).</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The PS signing keys, keyed by <c>kid</c>. Published at the JWKS and used
    /// to sign minted auth tokens (the first entry signs).
    /// </summary>
    public required IReadOnlyDictionary<string, IAAuthKey> SigningKeys { get; init; }

    /// <summary>The token endpoint path. Default <c>/token</c>.</summary>
    public string TokenPath { get; init; } = "/token";
    public string RevocationPath { get; init; } = "/revoke";
    public Action<AAuthRevocationOptions>? ConfigureRevocation { get; init; }

    /// <summary>The pending (poll) path prefix. Default <c>/pending</c>.</summary>
    public string PendingPathPrefix { get; init; } = "/pending";

    /// <summary>
    /// The fallback scope when the resource token carries none. Default empty:
    /// the spec makes <c>scope</c> OPTIONAL, so a scopeless resource token mints
    /// a scopeless auth token (still valid via its <c>sub</c>) rather than
    /// injecting an arbitrary scope.
    /// </summary>
    public string DefaultScope { get; init; } = "";
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>
    /// The PS-hosted interaction/consent path advertised on
    /// <c>requirement=interaction</c>. Default <c>/interaction</c>. The caller
    /// maps this endpoint and resolves the verdict against the shared
    /// <see cref="IPersonPendingStore"/>.
    /// </summary>
    public string InteractionPath { get; init; } = "/interaction";
    public BrowserConsentSessions? ResourceInteractionSessions { get; init; }

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
        if (!AAuth.AAuthUrl.IsHttpsOrLoopback(options.Issuer, options.EgressPolicy))
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
            if (!AAuth.AAuthUrl.IsHttpsOrLoopback(trustedAs, options.EgressPolicy))
            {
                throw new InvalidOperationException(
                    $"AAuthPersonServerOptions.TrustedAccessServers entry '{trustedAs}' must be an absolute https URL " +
                    "(loopback http allowed for development).");
            }
        }

        string signingKid = string.Empty;
        IAAuthKey signingKey = null!;
        foreach (var (kid, key) in options.SigningKeys)
        {
            signingKid = kid;
            signingKey = key;
            break;
        }

        var issuer = options.Issuer;
        var inventory = app.MapAAuthIssuerRevocation(issuer, AuthTokenBuilder.PersonDwk,
            signingKey, signingKid, options.RevocationPath, options.EgressPolicy, options.TimeProvider, options.ConfigureRevocation);
        var interactionPath = "/" + options.InteractionPath.Trim('/');
        var interactionPrefix = interactionPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : interactionPath;
        var interactionUrl = $"{issuer}{interactionPath}";

        var trustedAccessServers = new HashSet<string>(StringComparer.Ordinal);
        foreach (var asUrl in options.TrustedAccessServers ?? Array.Empty<string>())
        {
            trustedAccessServers.Add(asUrl);
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
            EgressPolicy = options.EgressPolicy,
            Issuer = options.Issuer,
            TokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = new Dictionary<string, IAAuthKey>(options.SigningKeys),
            InteractionEndpoint = options.InteractionEndpoint ?? interactionUrl,
            MissionEndpoint = options.MissionEndpoint,
            PermissionEndpoint = options.PermissionEndpoint,
            AuditEndpoint = options.AuditEndpoint,
            ScopesSupported = options.ScopesSupported,
            RevocationEndpoint = $"{issuer}{options.RevocationPath}",
        });

        // 2. Verification middleware. The agent signs with the jwt scheme
        //    with issuer verification; the browser-facing interaction
        //    endpoint carries no signature, so exclude it — plus any unsigned
        //    surfaces the PS declares (e.g. its own consent/admin page).
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
                && ctx.Request.Path != options.RevocationPath
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix)
                && !unsignedPrefixes.Any(p => ctx.Request.Path.StartsWithSegments(p)),
            branch => branch.UseAAuthVerification(new AAuthVerificationOptions { EgressPolicy = options.EgressPolicy,
                AcceptedSchemes = ["jwt"], Clock = () => options.TimeProvider.GetUtcNow() }));

        var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var asserter = app.Services.GetRequiredService<IIdentityClaimsAsserter>();
        var pending = app.Services.GetRequiredService<IPersonPendingStore>();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.PersonServer");
        PersonResourceInteraction.Map(app, pending, options);

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

        Task<IResult> MintEntry(PersonPendingEntry entry) => AuthTokenResponse.CreateTrackedAsync(() => Mint(
            entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey!,
            entry.Subject ?? throw new TokenVerificationException("Approved identity assertion is missing its directed subject."), entry.Tenant, entry.Roles, entry.Groups,
            entry.AdditionalClaims, entry.UpstreamAct, entry.Mission,
            entry.AgentTokenExpiresAt, entry.AuthorizationExpiresAt, entry.Account), entry.ExpiresAt, inventory, entry.SourceTokens, options.TimeProvider);

        string Mint(
            string resourceUrl, string agentId, string scope, IAAuthKey confirmationKey,
            string subject, string? tenant, IReadOnlyList<string>? roles, IReadOnlyList<string>? groups,
            IReadOnlyDictionary<string, JsonNode?>? additionalClaims, JsonObject? upstreamAct, MissionClaim? mission,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt, string? account = null) =>
            new AuthTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = options.Issuer,
                Audience = resourceUrl,
                Account = account,
                Agent = agentId,
                AgentConfirmationKey = confirmationKey,
                AgentTokenExpiresAt = agentTokenExpiresAt,
                AuthorizationExpiresAt = authorizationExpiresAt,
                TimeProvider = options.TimeProvider,
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
                return AAuth.Server.AAuthProblemDetails.Create("invalid_carrier_token", $"expected {AAuthConstants.TokenTypes.AgentToken}, got {ctx.GetAAuthTokenType()}", statusCode: StatusCodes.Status403Forbidden);
            }

            var agentId = (string?)parsed.Payload?["sub"];
            if (string.IsNullOrEmpty(agentId))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_carrier_token", "missing sub", statusCode: StatusCodes.Status403Forbidden);
            }

            TokenVerifier.VerifiedToken verifiedAgent;
            try
            {
                verifiedAgent = await tokenVerifier.VerifyWithJwksAsync(
                    parsed.Jwt!, metadataClient, jwksClient,
                    AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null);
                if (verifiedAgent.ExpiresAt.ToUnixTimeSeconds() <= options.TimeProvider.GetUtcNow().ToUnixTimeSeconds())
                    return AuthTokenResponse.Expired();
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.Create("invalid_agent_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            JsonObject? body;
            try
            {
                body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
            }
            catch (System.Text.Json.JsonException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceTokenJwt = (string?)body?["resource_token"];
            if (string.IsNullOrEmpty(resourceTokenJwt))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing resource_token", statusCode: StatusCodes.Status400BadRequest);
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
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "a sub-agent MUST NOT request authorization directly; the parent mediates (§Sub-Agents)", statusCode: StatusCodes.Status400BadRequest);
            }

            // Route on the resource token's `aud` (peeked, not trusted; both
            // branches fully verify the token afterwards). `aud == this PS` →
            // three-party collapsed mint; `aud == an AS` → four-party federation.
            var resourceAudience = PeekJwtAudience(resourceTokenJwt);
            if (resourceAudience is not null
                && !string.Equals(resourceAudience, issuer, StringComparison.Ordinal))
            {
                return await HandleFederatedAsync(
                    ctx, parsed, verifiedAgent, agentId, resourceTokenJwt, upstreamTokenJwt, subagentTokenJwt, resourceAudience, prompt, capabilities);
            }

            return await HandleThreePartyAsync(
                ctx, parsed, verifiedAgent, agentId, resourceTokenJwt, upstreamTokenJwt, subagentTokenJwt, prompt, capabilities);
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the agent polls the deferred verdict.
        // -------------------------------------------------------------------
        app.MapGet($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                // Mission-gate entries resolve through the consent seam + the
                // clarification protocol (§Agent Token Request gate 2c).
                if (entry.ExpiresAt.ToUnixTimeSeconds() <= options.TimeProvider.GetUtcNow().ToUnixTimeSeconds())
                    return AuthTokenResponse.Expired();
                if (entry.Mission is { } pendingMission
                    && await app.Services.GetRequiredService<IMissionStore>().GetAsync(pendingMission.S256)
                        is { State: MissionState.Terminated })
                {
                    entry.FederationCancellation.Cancel();
                    return GovernanceEndpoints.MissionTerminated();
                }
                if (entry.ResourceInteraction is { Error: not null } failedResource)
                    return AAuthProblemDetails.Create(failedResource.Error, statusCode: failedResource.ErrorStatus);
                if (entry.AwaitingResourceInteraction)
                    return Pending202(ctx, entry, options, interactionUrl);
                if (entry.ResumeAuthorization is { } resume)
                {
                    entry.ResumeAuthorization = null;
                    return await resume(ctx);
                }
                if (entry.MissionGate)
                {
                    return await ResolveMissionGateAsync(ctx, entry);
                }

                // Four-party entries resolve via the background federation task.
                if (entry.AgentConfirmationKey is null)
                {
                    if (entry.Status == PersonPendingStatus.AwaitingClarification)
                        return Pending202Clarification(ctx, entry, options);
                    if (entry.Status == PersonPendingStatus.Allowed && entry.AuthToken is not null)
                    {
                        return await AuthTokenResponse.CreateTrackedAsync(() => entry.AuthToken, entry.ExpiresAt,
                            inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
                    }
                    if (entry.Status == PersonPendingStatus.Denied)
                    {
                        if (!string.IsNullOrEmpty(entry.ErrorLocation))
                        {
                            ctx.Response.Headers.Location = entry.ErrorLocation;
                        }
                        return AAuth.Server.AAuthProblemDetails.Create(entry.Error ?? "denied", statusCode: entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
                    }
                    return Pending202(ctx, entry, options, interactionUrl);
                }

                // Three-party entries resolve when the host's interaction page marks
                // the verdict against the shared store.
                switch (entry.Status)
                {
                    case PersonPendingStatus.Allowed:
                        return await MintEntry(entry);
                    case PersonPendingStatus.Denied:
                        return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
                    case PersonPendingStatus.Pending:
                    default:
                        return Pending202(ctx, entry, options, interactionUrl);
                }
            });
        });

        // POST {PendingPathPrefix}/{id} — the agent answers a clarification
        // (§Agent Response to Clarification) or replaces its request. The SDK
        // records it in the mission log and readies the next review.
        app.MapPost($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }
            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                if (entry.Status == PersonPendingStatus.Withdrawn)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("request_withdrawn", statusCode: StatusCodes.Status410Gone);
                }

                JsonObject? body;
                try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
                catch (System.Text.Json.JsonException)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", statusCode: StatusCodes.Status400BadRequest);
                }

                var action = StringMember(body, "action");
                var answer = StringMember(body, "clarification_response");
                var updatedResourceToken = StringMember(body, "resource_token");
                if (entry.Status != PersonPendingStatus.AwaitingClarification
                    || action is not ("clarification_response" or "updated_request")
                    || (action == "clarification_response" && (string.IsNullOrWhiteSpace(answer) || body!.ContainsKey("resource_token")))
                    || (action == "updated_request" && (string.IsNullOrWhiteSpace(updatedResourceToken) || body!.ContainsKey("clarification_response")))
                    || (body!.ContainsKey("justification") && StringMember(body, "justification") is null))
                {
                    return AAuthProblemDetails.Create("invalid_request", "Expected a matching clarification action and payload on an awaiting clarification request.", statusCode: StatusCodes.Status400BadRequest);
                }
                if (entry.ClarificationRounds >= ClarificationExchange.DefaultMaxRounds)
                {
                    entry.Status = PersonPendingStatus.Denied;
                    return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: StatusCodes.Status403Forbidden);
                }
                if (action == "updated_request")
                {
                    try
                    {
                        var replacement = await tokenVerifier.VerifyResourceTokenAsync(updatedResourceToken!,
                            entry.ResourceAudience!, entry.AgentId, entry.ResourceKeyThumbprint!, metadataClient, jwksClient,
                            expectedApprover: issuer);
                        if (!string.Equals((string?)replacement.Payload["iss"], entry.ResourceUrl, StringComparison.Ordinal))
                            throw new TokenVerificationException("Replacement resource issuer differs from the original.");
                        if (!AccountBinding.Matches(entry.Account, replacement.Account))
                            throw new TokenVerificationException("Changing account requires a new authorization request.");
                        var replacementMission = MissionClaim.FromPayload(replacement.Payload, options.EgressPolicy);
                        if (entry.FederationMissionConsent is { Task.IsCompleted: false }
                            && (replacementMission?.Approver != entry.Mission?.Approver || replacementMission?.S256 != entry.Mission?.S256))
                            throw new TokenVerificationException("Changing a pending mission requires a new authorization request.");
                        if (entry.UpstreamAuthorization?.Mission is { } upstreamMission
                            && (replacementMission?.Approver != upstreamMission.Approver || replacementMission.S256 != upstreamMission.S256))
                            throw new TokenVerificationException("Replacement must retain the upstream mission.");
                        if (replacementMission is not null)
                        {
                            try { await ValidateMissionAsync(replacementMission, entry.ConsentAgentId, entry.UpstreamAuthorization); }
                            catch (AAuthTokenExchangeException ex)
                            {
                                return AAuthProblemDetails.Create(ex.ErrorCode, ex.Detail, statusCode: ex.StatusCode);
                            }
                        }
                        var replacementInteraction = await PersonResourceInteraction.CreateAsync(replacement.Payload,
                            updatedResourceToken!, options.EgressPolicy, ctx.RequestAborted);
                        entry.Scope = (string?)replacement.Payload["scope"] ?? options.DefaultScope;
                        entry.Mission = replacementMission;
                        entry.ResourceToken = updatedResourceToken;
                        entry.ResourceContext = (JsonObject)replacement.Payload.DeepClone();
                        entry.ResourceInteraction = replacementInteraction;
                        if (replacementInteraction is not null) entry.InteractionUrl = interactionUrl + "/resource";
                        entry.MissionGate = replacementMission is not null && (entry.AgentConfirmationKey is not null
                            || entry.FederationMissionConsent is { Task.IsCompleted: false });
                    }
                    catch (Exception ex) when (ex is TokenVerificationException or FormatException or InvalidOperationException or ArgumentException)
                    {
                        return AAuthProblemDetails.Create("invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
                    }
                }
                entry.ClarificationRounds++;
                if (StringMember(body, "justification") is { } justification)
                    entry.ClarificationAnswers.Add(justification);
                if (answer is not null)
                {
                    entry.ClarificationAnswers.Add(answer);
                }
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                if (entry.Mission is not null) await missionLog.AppendAsync(new MissionLogEntry(
                    entry.Mission.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
                {
                    Detail = answer ?? "updated_request",
                });
                // The clarification round is answered — re-review on the next poll.
                entry.ClarificationQuestion = null;
                entry.ClarificationDeadline = null;
                entry.Status = PersonPendingStatus.Pending;
                entry.Browser.Renew();
                entry.FederationAnswer?.TrySetResult(action == "updated_request"
                    ? ClarificationResponse.Update(updatedResourceToken!, StringMember(body, "justification"))
                    : ClarificationResponse.Respond(answer!));
                return Results.NoContent();
            });
        });

        // DELETE {PendingPathPrefix}/{id} — the agent withdraws the request
        // (§Agent Response to Clarification — cancel). A later poll returns 410.
        app.MapDelete($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuth.Server.DeferredState.Missing(id);
            if (!RequesterMatches(ctx, entry))
            {
                return AAuthProblemDetails.Create("unknown_interaction", statusCode: StatusCodes.Status404NotFound);
            }
            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                entry.Status = PersonPendingStatus.Withdrawn;
                entry.Lifecycle.Cancel();
                entry.FederationCancellation.Cancel();
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                if (entry.Mission is not null) await missionLog.AppendAsync(new MissionLogEntry(
                    entry.Mission.S256, MissionLogEntryKind.Clarification, DateTimeOffset.UtcNow)
                {
                    Detail = "cancelled",
                });
                return Results.NoContent();
            });
        });

        return app;

        // ---- mission-gate resolution (gate 2c) -----------------------------
        async Task<StoredMission> ValidateMissionAsync(MissionClaim mission, string consentAgentId, UpstreamTokenValidationResult? upstream)
        {
            var stored = await app.Services.GetRequiredService<IMissionStore>().GetAsync(mission.S256);
            if (stored is null || stored.Approver != issuer || mission.Approver != issuer)
                throw new AAuthTokenExchangeException("invalid_mission", "Mission approval is not known to this Person Server.", 403, true);
            var authorized = stored.Agent == consentAgentId;
            if (!authorized && upstream is { IsValid: true, Verified: not null } && upstream.Mission == mission)
            {
                authorized = upstream.Agent == stored.Agent;
                for (var ancestor = upstream.Verified.Payload["act"] as JsonObject; ancestor is not null; ancestor = ancestor["act"] as JsonObject)
                    authorized |= (string?)ancestor["agent"] == stored.Agent;
            }
            if (!authorized)
                throw new AAuthTokenExchangeException("invalid_mission", "Mission approval does not authorize this agent or verified delegation.", 403, true);
            if (stored.State == MissionState.Terminated)
                throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
            return stored;
        }

        async Task<(MissionTokenConsentDecision Decision, string Detail)> ReviewMissionAsync(MissionTokenConsentContext context)
        {
            var approval = await ValidateMissionAsync(context.Mission, context.ConsentAgentId ?? context.AgentId, context.UpstreamAuthorization);
            if (context.Stage == MissionTokenConsentStage.Gate
                && await app.Services.GetRequiredService<IMissionLog>().HasPriorConsentAsync(
                    context.Mission.S256, context.ResourceUrl, context.Scope, account: context.Account,
                    agentId: context.AgentId, agentKeyThumbprint: context.AgentKeyThumbprint))
                return (MissionTokenConsentDecision.Grant(), "PriorConsent");
            return (await app.Services.GetRequiredService<IMissionTokenConsent>().ReviewAsync(context with { ValidatedApproval = approval }), "InScope");
        }

        async Task<IResult> ResolveMissionGateAsync(HttpContext ctx, PersonPendingEntry entry)
        {
            if (entry.Mission is null)
                return Pending202(ctx, entry, options, interactionUrl);
            try { await ValidateMissionAsync(entry.Mission, entry.ConsentAgentId, entry.UpstreamAuthorization); }
            catch (AAuthTokenExchangeException ex)
            {
                entry.FederationMissionConsent?.TrySetException(ex);
                return AAuthProblemDetails.Create(ex.ErrorCode, ex.Detail, statusCode: ex.StatusCode);
            }
            var missionLog = app.Services.GetRequiredService<IMissionLog>();
            var s256 = entry.Mission!.S256;

            switch (entry.Status)
            {
                case PersonPendingStatus.Withdrawn:
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return AAuth.Server.AAuthProblemDetails.Create("request_withdrawn", statusCode: StatusCodes.Status410Gone);

                case PersonPendingStatus.AwaitingClarification:
                    return Pending202Clarification(ctx, entry, options);

                case PersonPendingStatus.Allowed:
                    // Resolved out-of-band by the PS's user channel (MarkAllowed).
                    return await MintMissionEntryAsync(entry);

                case PersonPendingStatus.Denied:
                    entry.FederationMissionConsent?.TrySetException(new AAuthInteractionDeniedException(entry.DenyReason ?? "Mission consent denied."));
                    if (!entry.MissionResolved)
                    {
                        await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                        entry.MissionResolved = true;
                    }
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);

                case PersonPendingStatus.Pending:
                default:
                    var (decision, _) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = entry.AgentId,
                        ConsentAgentId = entry.ConsentAgentId,
                        UpstreamAuthorization = entry.UpstreamAuthorization,
                        ResourceUrl = entry.ResourceUrl,
                        Account = entry.Account,
                        AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                        Scope = entry.Scope,
                        Mission = entry.Mission!,
                        Stage = MissionTokenConsentStage.Resolve,
                        Prompt = entry.Prompt,
                        Capabilities = entry.Capabilities,
                        ClarificationHistory = entry.ClarificationAnswers,
                        ResourceContext = entry.ResourceContext,
                    });
                    switch (decision.Kind)
                    {
                        case MissionTokenConsentKind.Grant:
                            return await ResolveMissionGrantAsync(entry);
                        case MissionTokenConsentKind.Deny:
                            await AppendMissionTokenDenialAsync(missionLog, s256, entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                            entry.MissionResolved = true;
                            entry.Status = PersonPendingStatus.Denied;
                            entry.DenyReason = decision.Reason ?? "the user denied this request";
                            entry.FederationMissionConsent?.TrySetException(new AAuthInteractionDeniedException(entry.DenyReason));
                            ctx.Response.Headers["Cache-Control"] = "no-store";
                            return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
                        case MissionTokenConsentKind.Clarify:
                            if (entry.ClarificationRounds >= ClarificationExchange.DefaultMaxRounds)
                                return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: 403);
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

        async Task<IResult> MintMissionEntryAsync(PersonPendingEntry entry)
        {
            if (entry.FederationMissionConsent is { } approval)
            {
                entry.MissionGate = false;
                entry.Status = PersonPendingStatus.Pending;
                approval.TrySetResult(true);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }
            var response = await MintEntry(entry);
            if (!entry.MissionResolved && response is IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
            {
                await AppendMissionTokenAsync(app.Services.GetRequiredService<IMissionLog>(), entry.Mission!.S256,
                    entry.ResourceUrl, entry.Scope, "OutOfScope", entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                entry.MissionResolved = true;
            }
            return response;
        }

        // Mint an out-of-scope grant: the asserter supplies identity, the verdict
        // is cached on the entry so a repeat poll is idempotent.
        async Task<IResult> ResolveMissionGrantAsync(PersonPendingEntry entry)
        {
            if (entry.FederationMissionConsent is not null)
                return await MintMissionEntryAsync(entry);
            var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = entry.ResourceUrl,
                Account = entry.Account,
                AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                Scope = entry.Scope,
                AgentId = entry.ConsentAgentId,
                Mission = entry.Mission,
                Prompt = entry.Prompt,
                Capabilities = entry.Capabilities,
                ResourceContext = entry.ResourceContext,
                UpstreamAuthorization = entry.UpstreamAuthorization,
            });
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                entry.Status = PersonPendingStatus.Denied;
                entry.DenyReason = asserted.Reason ?? "identity assertion failed";
                return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
            }
            entry.Subject = asserted.Subject;
            entry.Tenant = asserted.Tenant;
            entry.Roles = asserted.Roles;
            entry.Groups = asserted.Groups;
            entry.AdditionalClaims = asserted.AdditionalClaims;
            entry.Status = PersonPendingStatus.Allowed;
            return await MintMissionEntryAsync(entry);
        }

        // Silent grant (gate 2a / 2b): the asserter supplies identity, the SDK
        // mints immediately without parking.
        async Task<IResult> MintMissionGrantAsync(
            string audience, string boundAgentId, string scope, IAAuthKey confirmationKey,
            JsonObject? upstreamAct, MissionClaim mission, string? prompt,
            IReadOnlyList<string>? capabilities, string agentId,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset authorizationExpiresAt, IReadOnlyList<TokenKey> sources,
            string? account, string consentDetail, JsonObject resourceContext, UpstreamTokenValidationResult? upstreamAuthorization)
        {
            var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = audience,
                Account = account,
                AgentKeyThumbprint = confirmationKey.ComputeJwkThumbprint(),
                Scope = scope,
                AgentId = agentId,
                Mission = mission,
                Prompt = prompt,
                Capabilities = capabilities,
                ResourceContext = resourceContext,
                UpstreamAuthorization = upstreamAuthorization,
            });
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                return AAuth.Server.AAuthProblemDetails.Create("denied", asserted.Reason, statusCode: StatusCodes.Status403Forbidden);
            }
            var response = await AuthTokenResponse.CreateTrackedAsync(() => Mint(
                audience, boundAgentId, scope, confirmationKey,
                asserted.Subject ?? throw new TokenVerificationException("Approved identity assertion is missing its directed subject."), asserted.Tenant, asserted.Roles,
                asserted.Groups, asserted.AdditionalClaims, upstreamAct, mission,
                agentTokenExpiresAt, authorizationExpiresAt, account), authorizationExpiresAt, inventory, sources, options.TimeProvider);
            if (response is IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
                await AppendMissionTokenAsync(app.Services.GetRequiredService<IMissionLog>(), mission.S256,
                    audience, scope, consentDetail, account, boundAgentId, confirmationKey.ComputeJwkThumbprint());
            return response;
        }

        // ---- three-party (PS-asserted) handler -----------------------------
        async Task<IResult> HandleThreePartyAsync(
            HttpContext ctx, SignatureKeyParser.ParsedSignatureKeyInfo parsed,
            TokenVerifier.VerifiedToken verifiedAgent,
            string agentId, string resourceTokenJwt, string? upstreamTokenJwt, string? subagentTokenJwt,
            string? prompt = null, IReadOnlyList<string>? capabilities = null, PersonPendingEntry? resumed = null)
        {
            // Call-chaining: validate upstream_token (§Upstream Token Verification).
            JsonObject? upstreamAct = null;
            UpstreamTokenValidationResult? upstreamAuthorization = null;
            var agentTokenExpiresAt = verifiedAgent.ExpiresAt;
            var authorizationExpiresAt = verifiedAgent.ExpiresAt;
            var sourceRegistrations = new List<TokenRegistration> { TokenRegistration.FromVerified(verifiedAgent) };
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
                    var normalized = upstreamIss;
                    return string.Equals(normalized, issuer, StringComparison.Ordinal)
                        || trustedAccessServers.Contains(normalized)
                        || (options.IsTrustedAccessServer?.Invoke(normalized) ?? false);
                };

                var result = await validator.ValidateAsync(
                    upstreamTokenJwt,
                    expectedAudience: intermediaryResourceUrl,
                    isTrustedUpstreamIssuer);
                if (!result.IsValid)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_upstream_token", result.Error, statusCode: StatusCodes.Status400BadRequest);
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
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "call chaining from a four-party (AS-issued) upstream token requires a mission so the PS stays in the loop (§Call Chaining)", statusCode: StatusCodes.Status400BadRequest);
                }

                // Compose the downstream act node (§Delegation Chain): act.agent is
                // the upstream token's agent (the delegator), nesting the upstream's
                // own chain as act.act. `upstreamAct` now holds this complete node.
                upstreamAct = ActChainBuilder.BuildNestedAct(result.Agent!, result.UpstreamAct);
                upstreamAuthorization = result;
                sourceRegistrations.Add(TokenRegistration.FromVerified(result.Verified!));
                if (result.ExpiresAt!.Value < authorizationExpiresAt)
                    authorizationExpiresAt = result.ExpiresAt.Value;
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
                IAAuthKey subagentKey;
                string? subagentParent;
                try
                {
                    var verifiedSub = await tokenVerifier.VerifyWithJwksAsync(
                        subagentTokenJwt, metadataClient, jwksClient,
                        AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null);
                    sourceRegistrations.Add(TokenRegistration.FromVerified(verifiedSub));
                    subagentId = (string?)verifiedSub.Payload["sub"]
                        ?? throw new TokenVerificationException("subagent_token missing sub");
                    var subCnf = verifiedSub.Payload["cnf"]?["jwk"] as JsonObject
                        ?? throw new TokenVerificationException("subagent_token missing cnf.jwk");
                    subagentKey = KeyFactory.FromPublicJwk(subCnf);
                    subagentParent = (string?)verifiedSub.Payload["parent_agent"]
                        ?? throw new TokenVerificationException("subagent_token missing parent_agent");
                    agentTokenExpiresAt = verifiedSub.ExpiresAt;
                    if (agentTokenExpiresAt < authorizationExpiresAt)
                        authorizationExpiresAt = agentTokenExpiresAt;
                }
                catch (TokenVerificationException ex)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_agent_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
                }

                // The signing agent (parent) MUST be named by subagent_token.parent_agent.
                if (!string.Equals(subagentParent, agentId, StringComparison.Ordinal))
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "subagent_token.parent_agent does not name the signing agent (§Sub-Agents)", statusCode: StatusCodes.Status400BadRequest);
                }

                boundAgentId = subagentId;
                boundConfirmationKey = subagentKey;
                subagentJkt = subagentKey.ComputeJwkThumbprint();
                // Sub-agent act (§Delegation Chain): act.agent = the parent (the
                // signer that mediates). When the parent presented an upstream_token,
                // `upstreamAct` already records the parent as its top node; otherwise
                // build a single-node act naming the parent.
                boundUpstreamAct = ActChainBuilder.BuildNestedAct(agentId, upstreamAct);
            }

            // Verify the resource token (§Resource Token Verification). `iss`
            // becomes the auth token's `aud`; `scope` is echoed; `mission` (if
            // present) governs the request. For a sub-agent the resource token's
            // `agent`/`agent_jkt` bind to the sub-agent (step 6 uses subagentJkt).
            string audience;
            string? account;
            var requestedScope = options.DefaultScope;
            MissionClaim? missionClaim;
            JsonObject resourceContext;
            try
            {
                var verified = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: options.Issuer,
                    expectedAgentId: boundAgentId,
                    expectedAgentJkt: parsed.ConfirmationKey!.ComputeJwkThumbprint(),
                    metadataClient, jwksClient,
                    expectedApprover: issuer,
                    subagentAgentJkt: subagentJkt);


                audience = (string?)verified.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                resourceContext = (JsonObject)verified.Payload.DeepClone();
                account = verified.Account;
                var scopeClaim = (string?)verified.Payload["scope"];
                if (!string.IsNullOrWhiteSpace(scopeClaim))
                {
                    requestedScope = scopeClaim;
                }
                missionClaim = MissionClaim.FromPayload(verified.Payload, options.EgressPolicy);
                if (upstreamAuthorization?.Mission is { } upstreamMission
                    && (upstreamMission.Approver != issuer || missionClaim?.Approver != upstreamMission.Approver
                        || missionClaim.S256 != upstreamMission.S256))
                    throw new TokenVerificationException("Downstream request must retain its upstream mission and governing PS.");
            }
            catch (TokenVerificationException ex)
            {
                var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
                // §Token Endpoint Error Codes: invalid_resource_token / expired_resource_token
                // are 400 (a bad token parameter in the body), not 401 — 401 is reserved for
                // request-signature failures carrying a Signature-Error header (§Authentication
                // Errors). The request itself was correctly signed; the resource_token is invalid.
                return AAuth.Server.AAuthProblemDetails.Create(expired ? "expired_resource_token" : "invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            IReadOnlyList<TokenKey> sourceTokens;
            try { sourceTokens = await TokenRegistration.RegisterAsync(inventory, sourceRegistrations, ctx.RequestAborted); }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.Create("invalid_agent_token", ex.Message, statusCode: 400);
            }

            // Mission gate (§Agent Token Request, three-gate model). The SDK owns
            // the gate structure + the clarification protocol; IMissionTokenConsent
            // owns the out-of-scope decision (L3226 "does not prescribe how the
            // decision is made"). Identity claims on a grant come from the asserter.
            if (resumed is null && resourceContext.ContainsKey("interaction"))
            {
                if (missionClaim is not null)
                {
                    try { await ValidateMissionAsync(missionClaim, agentId, upstreamAuthorization); }
                    catch (AAuthTokenExchangeException ex)
                    { return AAuthProblemDetails.Create(ex.ErrorCode, ex.Detail, statusCode: ex.StatusCode); }
                }
                PersonResourceInteraction? resourceInteraction;
                try { resourceInteraction = await PersonResourceInteraction.CreateAsync(resourceContext, resourceTokenJwt, options.EgressPolicy, ctx.RequestAborted); }
                catch (TokenVerificationException) { return AAuthProblemDetails.Create("invalid_resource_token", statusCode: 400); }
                var resourceEntry = pending.Add(audience, requestedScope, boundAgentId, boundConfirmationKey,
                    agentTokenExpiresAt, boundUpstreamAct, missionClaim, authorizationExpiresAt);
                BindOwner(ctx, resourceEntry);
                BindResource(resourceEntry, resourceTokenJwt, options.Issuer, boundConfirmationKey);
                resourceEntry.SourceTokens = sourceTokens;
                resourceEntry.UpstreamAuthorization = upstreamAuthorization;
                resourceEntry.ResourceInteraction = resourceInteraction;
                resourceEntry.InteractionUrl = interactionUrl + "/resource";
                resourceEntry.Prompt = prompt;
                resourceEntry.Capabilities = capabilities;
                resourceEntry.ResumeAuthorization = active => HandleThreePartyAsync(active, parsed, verifiedAgent,
                    agentId, resourceEntry.ResourceToken!, upstreamTokenJwt, subagentTokenJwt, prompt, capabilities, resourceEntry);
                return Pending202(ctx, resourceEntry, options, interactionUrl);
            }

            if (missionClaim is not null)
            {
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
                var s256 = missionClaim.S256;

                // Gate 2a/2c: the consent seam decides in-scope-silent vs the
                // out-of-scope review (grant / deny / clarify / interactive hold).
                MissionTokenConsentDecision decision;
                string consentDetail;
                try
                {
                    (decision, consentDetail) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = boundAgentId,
                        ConsentAgentId = agentId,
                        UpstreamAuthorization = upstreamAuthorization,
                        ResourceContext = resourceContext,
                        ResourceUrl = audience,
                        Account = account,
                        AgentKeyThumbprint = boundConfirmationKey.ComputeJwkThumbprint(),
                        Scope = requestedScope,
                        Mission = missionClaim,
                        Stage = MissionTokenConsentStage.Gate,
                        Prompt = prompt,
                        Capabilities = capabilities,
                    });
                }
                catch (AAuthTokenExchangeException ex)
                {
                    return AAuthProblemDetails.Create(ex.ErrorCode, ex.Detail, statusCode: ex.StatusCode);
                }
                switch (decision.Kind)
                {
                    case MissionTokenConsentKind.Grant:
                        // Gate 2a: within the approved intent → silent grant.
                        return await MintMissionGrantAsync(
                            audience, boundAgentId, requestedScope, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities, agentId,
                            agentTokenExpiresAt, authorizationExpiresAt, sourceTokens, account, consentDetail, resourceContext, upstreamAuthorization);
                    case MissionTokenConsentKind.Deny:
                        await AppendMissionTokenDenialAsync(missionLog, s256, audience, requestedScope, account, boundAgentId, boundConfirmationKey.ComputeJwkThumbprint());
                        return AAuth.Server.AAuthProblemDetails.Create("denied", decision.Reason, statusCode: StatusCodes.Status403Forbidden);
                    case MissionTokenConsentKind.Clarify:
                        var clarifyEntry = resumed ?? ParkMissionGate(
                            pending, audience, requestedScope, boundAgentId, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities,
                            agentTokenExpiresAt, authorizationExpiresAt);
                        BindOwner(ctx, clarifyEntry);
                        clarifyEntry.MissionGate = true;
                        clarifyEntry.UpstreamAuthorization = upstreamAuthorization;
                        clarifyEntry.SourceTokens = sourceTokens;
                        BindResource(clarifyEntry, resourceTokenJwt, options.Issuer, boundConfirmationKey);
                        clarifyEntry.Status = PersonPendingStatus.AwaitingClarification;
                        clarifyEntry.ClarificationQuestion = decision.Question;
                        clarifyEntry.ClarificationTimeout = decision.Timeout;
                        clarifyEntry.ClarificationOptions = decision.Options;
                        return Pending202Clarification(ctx, clarifyEntry, options);
                    case MissionTokenConsentKind.Interact:
                    default:
                        var interactEntry = resumed ?? ParkMissionGate(
                            pending, audience, requestedScope, boundAgentId, boundConfirmationKey,
                            boundUpstreamAct, missionClaim, prompt, capabilities,
                            agentTokenExpiresAt, authorizationExpiresAt);
                        BindOwner(ctx, interactEntry);
                        interactEntry.MissionGate = true;
                        interactEntry.UpstreamAuthorization = upstreamAuthorization;
                        interactEntry.SourceTokens = sourceTokens;
                        BindResource(interactEntry, resourceTokenJwt, options.Issuer, boundConfirmationKey);
                        return Pending202(ctx, interactEntry, options, interactionUrl);
                }
            }

            // Non-mission three-party path.
            var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
            {
                ResourceUrl = audience,
                Account = account,
                AgentKeyThumbprint = boundConfirmationKey.ComputeJwkThumbprint(),
                Scope = requestedScope,
                AgentId = agentId,
                Prompt = prompt,
                Capabilities = capabilities,
                UpstreamAuthorization = upstreamAuthorization,
                ResourceContext = resourceContext,
            });
            switch (assertion.Kind)
            {
                case IdentityAssertionKind.Assert:
                    return await AuthTokenResponse.CreateTrackedAsync(() => Mint(
                        audience, boundAgentId, requestedScope, boundConfirmationKey,
                        assertion.Subject ?? throw new TokenVerificationException("Approved identity assertion is missing its directed subject."), assertion.Tenant, assertion.Roles,
                        assertion.Groups, assertion.AdditionalClaims, boundUpstreamAct, mission: null,
                        agentTokenExpiresAt, authorizationExpiresAt, account), authorizationExpiresAt, inventory, sourceTokens, options.TimeProvider, ctx.RequestAborted);
                case IdentityAssertionKind.Deny:
                    return AAuth.Server.AAuthProblemDetails.Create("denied", assertion.Reason, statusCode: StatusCodes.Status403Forbidden);
                case IdentityAssertionKind.NeedsConsent:
                default:
                    var entry = resumed ?? pending.Add(audience, requestedScope, boundAgentId, boundConfirmationKey,
                        agentTokenExpiresAt, boundUpstreamAct, authorizationExpiresAt: authorizationExpiresAt);
                    BindOwner(ctx, entry);
                    entry.SourceTokens = sourceTokens;
                    BindResource(entry, resourceTokenJwt, options.Issuer, boundConfirmationKey);
                    entry.UpstreamAuthorization = upstreamAuthorization;
                    return Pending202(ctx, entry, options, interactionUrl);
            }
        }

        // ---- four-party (federated) handler --------------------------------
        async Task<IResult> HandleFederatedAsync(
            HttpContext ctx, SignatureKeyParser.ParsedSignatureKeyInfo parsed,
            TokenVerifier.VerifiedToken verifiedAgent,
            string agentId, string resourceTokenJwt, string? upstreamTokenJwt, string? subagentTokenJwt, string resourceAudience,
            string? prompt, IReadOnlyList<string>? capabilities)
        {
            // §PS-AS Trust Establishment (L1581): trust may be pre-established OR
            // established dynamically — "no separate registration step". Default
            // open: federate to the AS named in the (verified) resource-token aud.
            // An empty TrustedAccessServers set disables four-party (three-party
            // only); a non-empty set and/or predicate restricts.
            if (!AAuthUrl.IsHttpsOrLoopback(resourceAudience, options.EgressPolicy))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_access_server", $"Access Server audience '{resourceAudience}' must be an absolute https URL (loopback http allowed for development).", statusCode: StatusCodes.Status400BadRequest);
            }
            if (!IssuerTrust.IsTrusted(trustedAccessServersOrNull, options.IsTrustedAccessServer, resourceAudience))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_access_server", $"'{resourceAudience}' is not a trusted Access Server.", statusCode: StatusCodes.Status403Forbidden);
            }

            // Verify the resource token's agent binding before forwarding it.
            AgentIssuanceContext issuance;
            IReadOnlyList<TokenKey> sourceTokens;
            try
            {
                issuance = await AgentIssuanceContext.VerifyAsync(parsed.Jwt!, subagentTokenJwt, upstreamTokenJwt,
                    tokenVerifier, metadataClient, jwksClient,
                    upstreamIssuer => string.Equals(upstreamIssuer, issuer, StringComparison.Ordinal)
                        || trustedAccessServers.Contains(upstreamIssuer)
                        || (options.IsTrustedAccessServer?.Invoke(upstreamIssuer) ?? false),
                    ctx.RequestAborted);
                sourceTokens = await TokenRegistration.RegisterAsync(inventory, issuance.SourceTokens, ctx.RequestAborted);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.Create("invalid_agent_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }
            string resourceUrl;
            JsonObject federatedContext;
            MissionClaim? federatedMission;
            var federatedScope = options.DefaultScope;
            try
            {
                var verified = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: resourceAudience,
                    expectedAgentId: issuance.AgentId,
                    expectedAgentJkt: issuance.ConfirmationKey.ComputeJwkThumbprint(),
                    metadataClient, jwksClient, expectedApprover: issuer);

                resourceUrl = (string?)verified.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                federatedContext = (JsonObject)verified.Payload.DeepClone();
                issuance.ValidateResourceContext(federatedContext, issuer);
                federatedMission = MissionClaim.FromPayload(verified.Payload, options.EgressPolicy);
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
                return AAuth.Server.AAuthProblemDetails.Create(expired ? "expired_resource_token" : "invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            if (federatedMission is not null)
            {
                try { await ValidateMissionAsync(federatedMission, agentId, issuance.Upstream); }
                catch (AAuthTokenExchangeException ex)
                { return AAuthProblemDetails.Create(ex.ErrorCode, ex.Detail, statusCode: ex.StatusCode); }
            }
            var federation = app.Services.GetRequiredService<AccessServerClient>();
            var entry = pending.Add(resourceUrl, federatedScope, issuance.AgentId, agentConfirmationKey: null,
                issuance.AgentTokenExpiresAt, issuance.Act, mission: federatedMission, authorizationExpiresAt: issuance.ExpiresAt);
            entry.ResourceContext = federatedContext;
            entry.UpstreamAuthorization = issuance.Upstream;
            entry.SourceTokens = sourceTokens;
            entry.Prompt = prompt;
            entry.Capabilities = capabilities;
            BindOwner(ctx, entry);
            BindResource(entry, resourceTokenJwt, resourceAudience, issuance.ConfirmationKey);
            try { entry.ResourceInteraction = await PersonResourceInteraction.CreateAsync(federatedContext, resourceTokenJwt, options.EgressPolicy, ctx.RequestAborted); }
            catch (TokenVerificationException) { return AAuthProblemDetails.Create("invalid_resource_token", statusCode: 400); }
            if (entry.AwaitingResourceInteraction)
            {
                entry.InteractionUrl = interactionUrl + "/resource";
                entry.FirstAnswer.TrySetResult();
            }

            string? consentedResourceToken = null;
            string? missionConsentedResourceToken = null;
            async Task<IdentityAssertion> RequireConsentAsync(IReadOnlyList<string>? requiredClaims, System.Threading.CancellationToken ct)
            {
                if (entry.ResourceInteraction is { } resourceInteraction
                    && !await resourceInteraction.Completion.Task.WaitAsync(ct))
                    throw new AAuthTokenExchangeException(resourceInteraction.Error!, null, resourceInteraction.ErrorStatus, true);
                if (entry.Mission is { } currentMission
                    && await app.Services.GetRequiredService<IMissionStore>().GetAsync(currentMission.S256)
                        is { State: MissionState.Terminated })
                    throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
                if (entry.Mission is { } mission && missionConsentedResourceToken != entry.ResourceToken)
                {
                    var (decision, _) = await ReviewMissionAsync(new MissionTokenConsentContext
                    {
                        AgentId = entry.AgentId, ResourceUrl = entry.ResourceUrl, Account = entry.Account,
                        ConsentAgentId = entry.ConsentAgentId, UpstreamAuthorization = entry.UpstreamAuthorization,
                        AgentKeyThumbprint = entry.ResourceKeyThumbprint, Scope = entry.Scope, Mission = mission,
                        Stage = MissionTokenConsentStage.Gate, Prompt = entry.Prompt, Capabilities = entry.Capabilities,
                        ResourceContext = entry.ResourceContext, ClarificationHistory = entry.ClarificationAnswers,
                    });
                    if (decision.Kind == MissionTokenConsentKind.Deny)
                    {
                        await AppendMissionTokenDenialAsync(app.Services.GetRequiredService<IMissionLog>(), mission.S256,
                            entry.ResourceUrl, entry.Scope, entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                        throw new AAuthInteractionDeniedException(decision.Reason ?? "Mission consent denied.");
                    }
                    if (decision.Kind is MissionTokenConsentKind.Clarify or MissionTokenConsentKind.Interact)
                    {
                        Task approval;
                        await entry.Lifecycle.Gate.WaitAsync(ct);
                        try
                        {
                            entry.MissionGate = true;
                            entry.FederationMissionConsent = new(TaskCreationOptions.RunContinuationsAsynchronously);
                            entry.Status = decision.Kind == MissionTokenConsentKind.Clarify
                                ? PersonPendingStatus.AwaitingClarification : PersonPendingStatus.Pending;
                            entry.ClarificationQuestion = decision.Question;
                            entry.ClarificationTimeout = decision.Timeout;
                            entry.ClarificationOptions = decision.Options;
                            entry.Browser.Renew();
                            approval = entry.FederationMissionConsent.Task;
                            entry.FirstAnswer.TrySetResult();
                        }
                        finally { entry.Lifecycle.Gate.Release(); }
                        await approval.WaitAsync(ct);
                        if (await app.Services.GetRequiredService<IMissionStore>().GetAsync(mission.S256)
                            is { State: MissionState.Terminated })
                            throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
                    }
                    missionConsentedResourceToken = entry.ResourceToken;
                }
                entry.RequiredIdentityClaims = requiredClaims;
                var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
                {
                    ResourceUrl = resourceUrl,
                    Account = entry.Account,
                    AgentKeyThumbprint = entry.ResourceKeyThumbprint,
                    Scope = entry.Scope,
                    AgentId = agentId,
                    RequiredClaims = requiredClaims,
                    Mission = entry.Mission,
                    Prompt = entry.Prompt,
                    Capabilities = entry.Capabilities,
                    ResourceContext = entry.ResourceContext,
                    InteractionId = entry.Id,
                    UpstreamAuthorization = issuance.Upstream,
                }, ct);
                if (asserted.Kind == IdentityAssertionKind.NeedsConsent)
                {
                    Task<IdentityAssertion> approval;
                    await entry.Lifecycle.Gate.WaitAsync(ct);
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        entry.FederationConsent = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        entry.Status = PersonPendingStatus.Pending;
                        entry.InteractionUrl = null;
                        entry.InteractionCode = null;
                        entry.Browser.Renew();
                        approval = entry.FederationConsent.Task;
                        entry.FirstAnswer.TrySetResult();
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                    asserted = await approval.WaitAsync(ct);
                }
                if (asserted.Kind != IdentityAssertionKind.Assert || string.IsNullOrWhiteSpace(asserted.Subject))
                    throw new AAuthInteractionDeniedException(asserted.Reason ?? "PS consent or directed identity was not asserted.");
                if (entry.Mission is { } assertedMission
                    && await app.Services.GetRequiredService<IMissionStore>().GetAsync(assertedMission.S256)
                        is { State: MissionState.Terminated })
                    throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
                consentedResourceToken = entry.ResourceToken;
                return asserted;
            }

            var agentTokenJwt = parsed.Jwt
                ?? throw new InvalidOperationException("Agent token JWT unavailable on the verified request.");
            var agentConfirmationKey = parsed.ConfirmationKey!;
            AccessServerRequest fedRequest = null!;
            fedRequest = new AccessServerRequest
            {
                ResourceToken = resourceTokenJwt,
                AgentToken = agentTokenJwt,
                SubagentToken = subagentTokenJwt,
                AuthorizationExpiresAt = issuance.ExpiresAt,
                UpstreamToken = upstreamTokenJwt,
                ExpectedAudience = resourceUrl,
                ExpectedAgentId = issuance.AgentId,
                AgentKey = issuance.ConfirmationKey,
                ExpectedActContext = issuance.Act,
                ExpectedMission = federatedMission,
                Account = entry.Account,
                RequestedScope = federatedScope,
                OnClarificationRequired = async (question, ct) =>
                {
                    var localAnswer = options.TriageClarificationAsync is { } triage
                        ? await triage(entry, question, ct) : null;
                    if (localAnswer is not null)
                    {
                        if (localAnswer.Action == ClarificationResponse.Kind.Update)
                        {
                            var replacement = await tokenVerifier.VerifyResourceTokenAsync(localAnswer.ResourceToken!,
                                resourceAudience, entry.AgentId, entry.ResourceKeyThumbprint!, metadataClient, jwksClient,
                                expectedApprover: issuer);
                            if ((string?)replacement.Payload["iss"] != entry.ResourceUrl)
                                throw new TokenVerificationException("Replacement issuer differs from original.");
                            if (!AccountBinding.Matches(entry.Account, replacement.Account))
                                throw new TokenVerificationException("Changing account requires a new authorization request.");
                            issuance.ValidateResourceContext(replacement.Payload, issuer);
                            if (MissionClaim.FromPayload(replacement.Payload, options.EgressPolicy) is { } replacementMission)
                                await ValidateMissionAsync(replacementMission, entry.ConsentAgentId, entry.UpstreamAuthorization);
                            var replacementInteraction = await PersonResourceInteraction.CreateAsync(replacement.Payload,
                                localAnswer.ResourceToken!, options.EgressPolicy, ct);
                            entry.Scope = (string?)replacement.Payload["scope"] ?? options.DefaultScope;
                            entry.ResourceToken = localAnswer.ResourceToken;
                            entry.ResourceContext = (JsonObject)replacement.Payload.DeepClone();
                            entry.Mission = MissionClaim.FromPayload(replacement.Payload, options.EgressPolicy);
                            entry.ResourceInteraction = replacementInteraction;
                            if (replacementInteraction is not null) entry.InteractionUrl = interactionUrl + "/resource";
                            fedRequest.RequestedScope = entry.Scope;
                            fedRequest.ExpectedMission = entry.Mission;
                        }
                        if (entry.ResourceToken != consentedResourceToken) await RequireConsentAsync(null, ct);
                        return localAnswer;
                    }
                    Task<ClarificationResponse> answer;
                    await entry.Lifecycle.Gate.WaitAsync(ct);
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        entry.FederationAnswer = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        entry.Status = PersonPendingStatus.AwaitingClarification;
                        entry.ClarificationQuestion = question.Clarification;
                        entry.ClarificationTimeout = question.TimeoutSeconds;
                        entry.ClarificationOptions = question.Options;
                        entry.ClarificationDeadline = options.TimeProvider.GetUtcNow().AddSeconds(question.TimeoutSeconds ?? 300);
                        answer = entry.FederationAnswer.Task;
                        entry.FirstAnswer.TrySetResult();
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                    var result = await answer.WaitAsync(ct);
                    issuance.ValidateResourceContext(entry.ResourceContext!, issuer);
                    fedRequest.RequestedScope = entry.Scope;
                    fedRequest.ExpectedMission = entry.Mission;
                    if (entry.ResourceToken != consentedResourceToken) await RequireConsentAsync(null, ct);
                    return result;
                },
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
                    var asserted = await RequireConsentAsync(claimsRequirement.RequiredClaims, ct);
                    return new ClaimsResponse
                    {
                        Subject = asserted.Subject!,
                        Claims = ProjectClaims(asserted, claimsRequirement.RequiredClaims),
                    };
                },
            };

            _ = Task.Run(async () =>
            {
                try
                {
                    entry.FederationCancellation.CancelAfter(entry.PendingExpiresAt - options.TimeProvider.GetUtcNow());
                    await RequireConsentAsync(null, entry.FederationCancellation.Token);
                    var token = await federation.FederateAsync(resourceAudience, fedRequest, entry.FederationCancellation.Token);
                    if (entry.Mission is { } completedMission
                        && await app.Services.GetRequiredService<IMissionStore>().GetAsync(completedMission.S256)
                            is { State: MissionState.Terminated })
                        throw new AAuthTokenExchangeException("mission_terminated", null, 403, true);
                    var tracked = await AuthTokenResponse.CreateTrackedAsync(() => token, entry.ExpiresAt,
                        inventory, entry.SourceTokens, options.TimeProvider, entry.FederationCancellation.Token);
                    if (tracked is not IStatusCodeHttpResult { StatusCode: StatusCodes.Status200OK })
                        throw new AAuthInteractionDeniedException("Source authorization was revoked before federation completed.");
                    if (entry.Mission is { } grantedMission)
                        await AppendMissionTokenAsync(app.Services.GetRequiredService<IMissionLog>(), grantedMission.S256,
                            entry.ResourceUrl, entry.Scope, "Federated", entry.Account, entry.AgentId, entry.ResourceKeyThumbprint);
                    await entry.Lifecycle.Gate.WaitAsync();
                    try
                    {
                        if (!entry.Lifecycle.Cancelled && !entry.Lifecycle.Delivered
                            && entry.Status != PersonPendingStatus.Denied && !entry.AwaitingFederationConsent
                            && consentedResourceToken == entry.ResourceToken)
                        {
                            entry.AuthToken = token;
                            entry.Status = PersonPendingStatus.Allowed;
                        }
                    }
                    finally { entry.Lifecycle.Gate.Release(); }
                }
                catch (Exception ex) when (ex is OperationCanceledException or AAuthClarificationCancelledException)
                {
                    entry.Error = "expired";
                    entry.ErrorStatus = StatusCodes.Status408RequestTimeout;
                    entry.Status = PersonPendingStatus.Denied;
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
                    logger.LogWarning("Four-party federation failed. Status={StatusCode}; Error={ErrorCode}.",
                        ex is System.Net.Http.HttpRequestException requestError ? (int?)requestError.StatusCode : null,
                        "federation_failed");
                    entry.Status = PersonPendingStatus.Denied;
                }
                finally
                {
                    entry.FirstAnswer.TrySetResult();
                }
            });

            await entry.FirstAnswer.Task;

            if (entry.AwaitingResourceInteraction)
                return Pending202(ctx, entry, options, interactionUrl);

            if (entry.MissionGate && entry.Status != PersonPendingStatus.AwaitingClarification)
                return Pending202(ctx, entry, options, interactionUrl);
            if (entry.AwaitingFederationConsent)
                return Pending202(ctx, entry, options, interactionUrl);

            if (entry.Status == PersonPendingStatus.AwaitingClarification)
                return Pending202Clarification(ctx, entry, options);

            if (entry.InteractionUrl is not null)
            {
                ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                ctx.Response.Headers["Retry-After"] = "1";
                ctx.Response.Headers["Cache-Control"] = "no-store";
                ctx.Response.Headers[AAuthRequirementHeader.Name] =
                    Interaction.Format(entry.InteractionUrl, entry.InteractionCode!, options.EgressPolicy);
                return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }

            if (entry.Status == PersonPendingStatus.Allowed)
            {
                return await AuthTokenResponse.CreateTrackedAsync(() => entry.AuthToken!, entry.ExpiresAt,
                    inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
            }

            if (!string.IsNullOrEmpty(entry.ErrorLocation))
            {
                ctx.Response.Headers.Location = entry.ErrorLocation;
            }
            return AAuth.Server.AAuthProblemDetails.Create(entry.Error ?? "denied", statusCode: entry.ErrorStatus ?? StatusCodes.Status403Forbidden);
        }
    }

    private static PersonPendingEntry ParkMissionGate(
        IPersonPendingStore pending, string audience, string scope, string agentId,
        IAAuthKey confirmationKey, JsonObject? upstreamAct, MissionClaim mission,
        string? prompt, IReadOnlyList<string>? capabilities,
        DateTimeOffset agentTokenExpiresAt, DateTimeOffset authorizationExpiresAt)
    {
        var entry = pending.Add(audience, scope, agentId, confirmationKey,
            agentTokenExpiresAt, upstreamAct, mission, authorizationExpiresAt);
        entry.MissionGate = true;
        entry.Prompt = prompt;
        entry.Capabilities = capabilities;
        return entry;
    }

    private static IResult Pending202(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options, string interactionUrl)
    {
        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
        // Human-consent wait: poll at ~1s (a browser approval takes seconds), not the
        // 100ms MinPollInterval floor a `Retry-After: 0` would clamp to. Matches the
        // four-party interaction path and the AS/Concierge/R3 endpoints.
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format(
            entry.InteractionUrl ?? interactionUrl, entry.InteractionCode ?? entry.Browser.Code, options.EgressPolicy);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // True when the verified carrier on this request is the agent that parked the
    // entry — guards the clarification POST/DELETE so one agent cannot answer or
    // withdraw another's pending request (the signature is already verified).
    private static bool RequesterMatches(HttpContext ctx, PersonPendingEntry entry)
    {
        var parsed = ctx.GetAAuthParsedKey();
        return ctx.GetAAuthTokenType() == AAuthTokenType.AgentToken
            && entry.OwnerIssuer is not null && entry.OwnerSubject is not null
            && entry.OwnerKeyThumbprint is not null
            && string.Equals((string?)parsed?.Payload?["iss"], entry.OwnerIssuer, StringComparison.Ordinal)
            && string.Equals((string?)parsed?.Payload?["sub"], entry.OwnerSubject, StringComparison.Ordinal)
            && string.Equals(parsed?.ConfirmationKey?.ComputeJwkThumbprint(), entry.OwnerKeyThumbprint, StringComparison.Ordinal);
    }

    private static void BindOwner(HttpContext ctx, PersonPendingEntry entry)
    {
        var parsed = ctx.GetAAuthParsedKey()!;
        entry.OwnerIssuer = (string?)parsed.Payload?["iss"];
        entry.OwnerSubject = (string?)parsed.Payload?["sub"];
        entry.OwnerKeyThumbprint = parsed.ConfirmationKey!.ComputeJwkThumbprint();
    }

    private static void BindResource(PersonPendingEntry entry, string resourceToken, string audience, IAAuthKey key)
    {
        entry.ResourceContext = TokenVerifier.DecodeJsonSegment(resourceToken.Split('.')[1], "payload");
        entry.ResourceToken = resourceToken;
        entry.ResourceAudience = audience;
        entry.ResourceKeyThumbprint = key.ComputeJwkThumbprint();
    }

    private static string? StringMember(JsonObject? body, string name) =>
        body?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    // The §requirement-clarification 202: emit the AAuth-Requirement header and a
    // body carrying the question (plus optional timeout/options).
    private static IResult Pending202Clarification(
        HttpContext ctx, PersonPendingEntry entry, AAuthPersonServerOptions options)
    {
        entry.ClarificationDeadline ??= options.TimeProvider.GetUtcNow().AddSeconds(entry.ClarificationTimeout ?? 300);
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
        IMissionLog missionLog, string s256, string resource, string scope,
        string? account, string? agentId, string? agentKeyThumbprint)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = false,
            Account = account,
            AgentId = agentId,
            AgentKeyThumbprint = agentKeyThumbprint,
            Detail = "OutOfScope",
        });

    private static Task AppendMissionTokenAsync(
        IMissionLog missionLog, string s256, string resource, string scope, string detail,
        string? account, string? agentId, string? agentKeyThumbprint)
        => missionLog.AppendAsync(new MissionLogEntry(s256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = resource,
            Scope = scope,
            Granted = true,
            Account = account,
            AgentId = agentId,
            AgentKeyThumbprint = agentKeyThumbprint,
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
                    if (!AuthTokenBuilder.IsReservedClaim(name) && asserted.AdditionalClaims is not null
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
