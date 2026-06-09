using System;
using System.Collections.Generic;
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
    /// Access Server URLs this PS will federate to (four-party). When a resource
    /// token's <c>aud</c> identifies one of these, the PS forwards a signed
    /// PS→AS request via <see cref="AccessServerClient"/> instead of minting
    /// itself. Empty disables the four-party branch (every request must be
    /// audienced to this PS).
    /// </summary>
    public IReadOnlyCollection<string>? TrustedAccessServers { get; init; }
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

        // 1. Well-known metadata + JWKS (reachable without a signature).
        WellKnownEndpoints.MapAAuthPersonServerWellKnown(app, new AAuthPersonServerMetadataOptions
        {
            Issuer = options.Issuer,
            TokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = new Dictionary<string, AAuthKey>(options.SigningKeys),
            InteractionEndpoint = interactionUrl,
        });

        // 2. Verification middleware. The agent signs with the jwt scheme
        //    (RequireIssuerVerification=false); the browser-facing interaction
        //    endpoint carries no signature, so exclude it.
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix),
            branch => branch.UseAAuthVerification(new AAuthVerificationOptions
            {
                RequireIssuerVerification = false,
            }));

        var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var asserter = app.Services.GetRequiredService<IIdentityClaimsAsserter>();
        var pending = app.Services.GetRequiredService<IPersonPendingStore>();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.PersonServer");

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
                UpstreamAct = upstreamAct,
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
                    if (entry.Mission is not null)
                    {
                        await AppendMissionGrantAsync(app, entry, "Consent");
                    }
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

        return app;

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
                var result = await validator.ValidateAsync(
                    upstreamTokenJwt,
                    expectedAudience: intermediaryResourceUrl,
                    new HashSet<string> { issuer });
                if (!result.IsValid)
                {
                    return Results.Json(new { error = "invalid_upstream_token", detail = result.Error },
                        statusCode: StatusCodes.Status400BadRequest);
                }
                upstreamAct = result.UpstreamAct;
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
                // act chain: { sub: subagent, act: { sub: parent[, act: upstream] } }.
                boundUpstreamAct = new JsonObject { ["sub"] = agentId };
                if (upstreamAct is not null)
                {
                    boundUpstreamAct["act"] = upstreamAct.DeepClone();
                }
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

            // Mission gate (§Agent Token Request, three-gate model).
            if (missionClaim is not null)
            {
                var missionStore = app.Services.GetRequiredService<IMissionStore>();
                var missionLog = app.Services.GetRequiredService<IMissionLog>();
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
                    var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
                    {
                        ResourceUrl = audience,
                        Scope = requestedScope,
                        AgentId = agentId,
                        Mission = missionClaim,
                        Prompt = prompt,
                        Capabilities = capabilities,
                    });
                    return MintFromAssertion(
                        asserted, audience, boundAgentId, requestedScope,
                        boundConfirmationKey, boundUpstreamAct, missionClaim)
                        ?? Results.Json(new { error = "denied", detail = asserted.Reason },
                            statusCode: StatusCodes.Status403Forbidden);
                }

                // Gate 2a / 3: the asserter decides in-scope (silent) vs prompt.
                var decision = await asserter.AssertAsync(new IdentityAssertionRequest
                {
                    ResourceUrl = audience,
                    Scope = requestedScope,
                    AgentId = agentId,
                    Mission = missionClaim,
                    Prompt = prompt,
                    Capabilities = capabilities,
                });
                switch (decision.Kind)
                {
                    case IdentityAssertionKind.Assert:
                        await AppendMissionTokenAsync(missionLog, s256, audience, requestedScope, "InScope");
                        return Results.Ok(new
                        {
                            auth_token = Mint(
                                audience, boundAgentId, requestedScope, boundConfirmationKey,
                                decision.Subject ?? "pairwise-sub", decision.Tenant, decision.Roles,
                                decision.Groups, decision.AdditionalClaims, boundUpstreamAct, missionClaim),
                        });
                    case IdentityAssertionKind.Deny:
                        return Results.Json(new { error = "denied", detail = decision.Reason },
                            statusCode: StatusCodes.Status403Forbidden);
                    case IdentityAssertionKind.NeedsConsent:
                    default:
                        var missionEntry = pending.Add(
                            audience, requestedScope, boundAgentId, boundConfirmationKey, boundUpstreamAct, missionClaim);
                        return Pending202(ctx, missionEntry, options, interactionUrl);
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
            if (trustedAccessServers.Count == 0
                || !trustedAccessServers.Contains(resourceAudience.TrimEnd('/')))
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

        IResult? MintFromAssertion(
            IdentityAssertion asserted, string audience, string agentId, string scope,
            IAAuthKey confirmationKey, JsonObject? upstreamAct, MissionClaim? mission)
        {
            if (asserted.Kind != IdentityAssertionKind.Assert)
            {
                return null;
            }
            return Results.Ok(new
            {
                auth_token = Mint(
                    audience, agentId, scope, confirmationKey,
                    asserted.Subject ?? "pairwise-sub", asserted.Tenant, asserted.Roles,
                    asserted.Groups, asserted.AdditionalClaims, upstreamAct, mission),
            });
        }
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

    private static async Task AppendMissionGrantAsync(WebApplication app, PersonPendingEntry entry, string detail)
    {
        var missionLog = app.Services.GetRequiredService<IMissionLog>();
        await AppendMissionTokenAsync(missionLog, entry.Mission!.S256, entry.ResourceUrl, entry.Scope, detail);
    }

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
