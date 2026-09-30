using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AAuth.Access;

/// <summary>
/// Configuration for <see cref="AAuthAccessServerEndpoints.MapAAuthAccessServer"/>.
/// </summary>
public sealed class AAuthAccessServerOptions
{
    public AAuthEgressPolicy EgressPolicy { get; set; } = AAuthEgressPolicy.Production;
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>HTTPS URL of this Access Server (<c>iss</c> of minted auth tokens).</summary>
    public string Issuer { get; set; } = "";

    /// <summary>
    /// The AS signing keys, keyed by <c>kid</c>. Published at the JWKS; minted tokens are
    /// signed with the active key.
    /// </summary>
    public AAuthSigningKeySet SigningKeys { get; set; } = new();

    /// <summary>
    /// A handle in the registered <see cref="IKeyStore"/> to load the signing key from when
    /// <see cref="SigningKeys"/> is empty.
    /// </summary>
    public string? KeyHandle { get; set; }

    /// <summary>The <c>kid</c> for the key loaded from <see cref="KeyHandle"/> (default: its thumbprint).</summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// Serve this instance only for requests whose <c>Host</c> is the issuer's authority.
    /// Required when several AAuth roles or instances share one host.
    /// </summary>
    public bool MatchIssuerHost { get; set; }

    /// <summary>The token endpoint path. Default <c>/token</c>.</summary>
    public string TokenPath { get; set; } = "/token";
    public string RevocationPath { get; set; } = "/revoke";
    public Action<AAuthRevocationOptions>? ConfigureRevocation { get; set; }

    /// <summary>The pending (poll/push) path prefix. Default <c>/pending</c>.</summary>
    public string PendingPathPrefix { get; set; } = "/pending";

    /// <summary>
    /// The fallback scope when the resource token carries none. Default empty:
    /// the spec makes <c>scope</c> OPTIONAL, so a scopeless resource token mints
    /// a scopeless auth token (still valid via its <c>sub</c>) rather than
    /// injecting an arbitrary scope.
    /// </summary>
    public string DefaultScope { get; set; } = "";

    /// <summary>
    /// Trust for this Access Server. <see cref="AAuthTrustOptions.PersonServers"/> is
    /// matched on the calling Person Server's identifier. <b>Open by default
    /// (spec-compliant):</b> any validly-signed PS is brokered; §PS-AS Trust
    /// Establishment requires no separate registration step. An <b>empty</b>
    /// <see cref="AAuthTrustRule.Allowed"/> set denies all.
    /// </summary>
    public AAuthTrustOptions Trust { get; set; } = new();

    /// <summary>
    /// Optional hook deriving baseline policy claims from the verified agent id
    /// (e.g. a demo admin-role convention). A production AS receives the
    /// principal's claims via the §Claims Required push instead.
    /// </summary>
    public Func<string, JsonObject?>? DeriveAgentClaims { get; set; }

    /// <summary>
    /// The AS-hosted login path advertised on <c>requirement=interaction</c>.
    /// Default <c>/interaction/login</c>. The caller maps this endpoint and
    /// resolves the verdict against the shared <see cref="IAccessPendingStore"/>.
    /// </summary>
    public string InteractionLoginPath { get; set; } = "/interaction/login";
}

/// <summary>
/// Maps the Access Server token endpoint, pending poll/push endpoints, and
/// well-known metadata in one call — the four-party counterpart to
/// <c>MapAAuthResource</c>. The AAuth crypto (signature verification, token
/// verification, minting, the §Claims Required composition) lives here; only
/// the allow/deny/defer decision is delegated to the DI-registered
/// <see cref="IAccessPolicy"/>.
/// </summary>
public static class AAuthAccessServerEndpoints
{
    /// <summary>
    /// Configure the AS pipeline: publish <c>/.well-known/aauth-access.json</c>
    /// + JWKS, add the request-signature verification middleware (excluding the
    /// well-known and interaction paths), and map the token + pending endpoints.
    /// Resolves <see cref="TokenVerifier"/>, <see cref="MetadataClient"/>,
    /// <see cref="JwksClient"/>, <see cref="IAccessPolicy"/>, and
    /// <see cref="IAccessPendingStore"/> from DI.
    /// </summary>
    public static WebApplication MapAAuthAccessServer(this WebApplication app, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        name ??= AAuthAccessServerBuilder.DefaultName;
        var identity = app.Services.GetKeyedService<IAAuthServerIdentity>(name)
            ?? throw new InvalidOperationException($"No Access Server named '{name}' is registered; call AddAAuthAccessServer first.");
        var options = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<AAuthAccessServerOptions>>().Get(name);
        _ = identity.SigningKeys.Active;

        var issuer = options.Issuer;
        var (routes, inScope) = AAuthServerRoles.Scope(app, issuer, options.MatchIssuerHost);
        var inventory = RevocationEndpoint.MapIssuerRevocationCore(app, routes, inScope,
            app.Services.GetRequiredKeyedService<AAuthRevocationService>(name), options.RevocationPath, options.ConfigureRevocation);
        var loginPath = "/" + options.InteractionLoginPath.Trim('/');
        var interactionPrefix = loginPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : loginPath;
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.AccessServer");
        AAuthServerRoles.RejectDevelopmentLoopbackInProduction(app.Services, $"Access Server '{name}'", options.EgressPolicy);
        AAuthServerRoles.WarnOnDevelopmentLoopback(app.Services, logger, "Access Server", name, options.EgressPolicy);

        // Startup footgun guard (diagnostics only): warn when brokering is open by
        // default. Suppressed by any explicit policy (including AAuthTrust.Any).
        TrustConfigDiagnostics.WarnIfOpenFederation(
            logger,
            trustConfigured: options.Trust.IsConfigured(AAuthTrustedParty.PersonServer, app.Services),
            "MapAAuthAccessServer",
            "this Access Server brokers for any verifiable Person Server because no Trust.PersonServers " +
            "policy is configured (the AAuth spec default). Configure a policy to " +
            "restrict, or assign AAuthTrust.Any to declare intentional open brokering and silence this warning.");

        // 1. Well-known metadata + JWKS (reachable without a signature).
        WellKnownEndpoints.MapAAuthAccessServerWellKnown(routes, new AAuthAccessServerMetadataOptions
        {
            EgressPolicy = options.EgressPolicy,
            Issuer = options.Issuer,
            AuthTokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = options.SigningKeys,
            RevocationEndpoint = $"{issuer}{options.RevocationPath}",
        });

        // 2. Verification middleware. The PS signs with the jwks_uri scheme
        //    with verified metadata discovery; the browser-facing interaction
        //    endpoints carry no signature, so exclude them.
        app.UseWhen(
            ctx => inScope(ctx)
                && !ctx.Request.Path.StartsWithSegments("/.well-known")
                && !ctx.Request.Path.StartsWithSegments(options.RevocationPath)
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix),
            branch => branch.UseAAuthVerificationCore(new AAuthVerificationOptions { EgressPolicy = options.EgressPolicy, AcceptedSchemes = ["jwks_uri"], RequireBodyCoverage = true, TimeProvider = options.TimeProvider }));

        var tokenVerifier = app.Services.GetRequiredKeyedService<TokenVerifier>(name);
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var policy = app.Services.GetRequiredKeyedService<IAccessPolicy>(name);
        var pending = app.Services.GetRequiredKeyedService<IAccessPendingStore>(name);
        AAuthServerRoles.WarnOnInMemoryDefaults(app.Services, logger, "Access Server", name, pending, inventory);

        bool IsVerifiedPersonServer(HttpContext context)
        {
            var parsed = context.GetAAuthParsedKey();
            return parsed?.Scheme == AAuthConstants.Schemes.JwksUri
                && parsed.Dwk == AAuthConstants.DwkFiles.Person
                && options.EgressPolicy.IsValidIdentifier(parsed.Identifier)
                && string.Equals(parsed.Identifier, context.GetAAuthVerification()?.Issuer, StringComparison.Ordinal);
        }

        // Re-pin a pending poll/push caller: it MUST present the jwks_uri
        // scheme, its host MUST be trusted (when a trust set is configured),
        // and it MUST be the same Person Server that parked the entry. Returns
        // a failure result, or null when authorized.
        async Task<IResult?> AuthorizePsCallerAsync(HttpContext c, AccessPendingEntry entry)
        {
            var parsedKey = c.GetAAuthParsedKey();
            if (parsedKey is null || parsedKey.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_carrier", "expected jwks_uri scheme", statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!IsVerifiedPersonServer(c))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "A verified Person Server metadata role is required.", statusCode: StatusCodes.Status403Forbidden);
            }

            if (!await options.Trust.IsTrustedAsync(parsedKey.Identifier!, AAuthTrustedParty.PersonServer,
                    c.RequestServices, c, cancellationToken: c.RequestAborted).ConfigureAwait(false))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", $"jwks_uri '{parsedKey.JwksUri}' is not a trusted Person Server", statusCode: StatusCodes.Status403Forbidden);
            }

            if (entry.OriginPersonServerHost is not { Length: > 0 } origin
                || !string.Equals(origin, parsedKey.Identifier, StringComparison.Ordinal)
                || entry.OwnerKeyThumbprint is null
                || !string.Equals(entry.OwnerKeyThumbprint, c.GetAAuthVerification()?.Jkt, StringComparison.Ordinal))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "pending entry belongs to a different Person Server", statusCode: StatusCodes.Status403Forbidden);
            }

            return null;
        }

        // §Auth Token Structure: `ps`, `sub`, `tenant`, `mission_s256` and `account`
        // are copied from the verified resource token (and so from the presented
        // token); policy supplies scope and any additional identity claims.
        ValueTask<string> Mint(CancellationToken cancellationToken,
            string resourceUrl, string scope, IAAuthKey confirmationKey, JsonObject resourceContext,
            string? tenant, IReadOnlyDictionary<string, JsonNode?>? additionalClaims,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt,
            IReadOnlyList<string>? roles = null, IReadOnlyList<string>? groups = null)
        {
            var (signingKid, signingKey) = options.SigningKeys.Active;
            return new AuthTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = options.Issuer,
                PersonServer = (string?)resourceContext["ps"]
                    ?? throw new TokenVerificationException("Resource token is missing 'ps'."),
                Audience = resourceUrl,
                AgentConfirmationKey = confirmationKey,
                AgentTokenExpiresAt = agentTokenExpiresAt,
                AuthorizationExpiresAt = authorizationExpiresAt,
                TimeProvider = options.TimeProvider,
                MissionS256 = MissionReference.Read(resourceContext),
                Account = AccountBinding.Read(resourceContext),
                Key = signingKey,
                KeyId = signingKid,
                Subject = (string?)resourceContext["sub"]
                    ?? throw new TokenVerificationException("Resource token is missing 'sub'."),
                Scope = scope,
                Tenant = (string?)resourceContext["tenant"] ?? tenant,
                Roles = roles,
                Groups = groups,
                Dwk = AuthTokenBuilder.AccessDwk,
                AdditionalClaims = additionalClaims,
            }.BuildAsync(cancellationToken);
        }

        // -------------------------------------------------------------------
        // POST {TokenPath} — the AS token endpoint (§PS-to-AS Token Request).
        // -------------------------------------------------------------------
        routes.MapPost(options.TokenPath, async (HttpContext ctx) =>
        {
            var parsed = ctx.GetAAuthParsedKey()!;
            // §PS-AS Federation: the PS is the only entity that calls AS token endpoints.
            if (parsed.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", $"expected jwks_uri scheme, got {parsed.Scheme}", statusCode: StatusCodes.Status401Unauthorized);
            }
            var personServer = parsed.Identifier!;
            if (!IsVerifiedPersonServer(ctx))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "A verified Person Server metadata role is required.", statusCode: StatusCodes.Status403Forbidden);
            }
            if (!await options.Trust.IsTrustedAsync(personServer, AAuthTrustedParty.PersonServer,
                    ctx.RequestServices, ctx, cancellationToken: ctx.RequestAborted).ConfigureAwait(false))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", $"jwks_uri '{parsed.JwksUri}' is not a trusted Person Server", statusCode: StatusCodes.Status403Forbidden);
            }

            JsonObject? body;
            try
            {
                body = await TokenRequestBody.ReadAsync(ctx.Request, tokenVerifier);
            }
            catch (System.Text.Json.JsonException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
            }
            catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }

            var agentTokenJwt = StringMember(body, "agent_token");
            var resourceTokenJwt = StringMember(body, "resource_token");
            var presentedTokenJwt = StringMember(body, "presented_token");
            if (string.IsNullOrEmpty(agentTokenJwt) || string.IsNullOrEmpty(resourceTokenJwt) || string.IsNullOrEmpty(presentedTokenJwt))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "agent_token, resource_token and presented_token are required", statusCode: StatusCodes.Status400BadRequest);
            }

            // Verify the agent, sub-agent and upstream tokens. At the AS an upstream
            // person token's iss / auth token's ps MUST be the signing PS; the
            // upstream auth token's iss is not checked beyond its signature.
            AgentIssuanceContext issuance;
            try
            {
                issuance = await AgentIssuanceContext.VerifyAsync(
                    agentTokenJwt, StringMember(body, "subagent_token"), StringMember(body, "upstream_token"), personServer,
                    tokenVerifier, metadataClient, jwksClient, static (_, _) => ValueTask.FromResult(true), ctx.RequestAborted, TokenCredential.Agent);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex);
            }

            // §Resource Token Verification: `aud` is this AS, `agent_jkt` the key the
            // auth token will bind, `ps` the signing PS; the presented token pairs by
            // jti/ps/sub/mission_s256/tenant.
            TokenVerifier.VerifiedToken resource, presented;
            try
            {
                resource = await tokenVerifier.VerifyResourceTokenAsync(resourceTokenJwt, options.Issuer,
                    issuance.ConfirmationKey.ComputeJwkThumbprint(), metadataClient, jwksClient,
                    expectedPersonServer: personServer, cancellationToken: ctx.RequestAborted);
                _ = resource.Account;
                // §Token Revocation: a resource token its resource withdrew never backs an auth token.
                if (await inventory.IsRevokedAsync(TokenRegistration.FromVerified(resource).Token, ctx.RequestAborted))
                    throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.RevokedJwt, "The resource token has been revoked.");
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
            }
            try
            {
                presented = await tokenVerifier.WithLocalIssuer(issuer, options.SigningKeys)
                    .VerifyPresentedTokenAsync(presentedTokenJwt, resource, metadataClient, jwksClient, ctx.RequestAborted);
                issuance.ValidateResourceContext(resource.Payload);
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
            }

            var agentId = issuance.AgentId;
            var agentConfirmationKey = issuance.ConfirmationKey;
            var agentTokenExpiresAt = issuance.AgentTokenExpiresAt;
            var ceiling = presented.ExpiresAt < issuance.ExpiresAt ? presented.ExpiresAt : issuance.ExpiresAt;
            var audience = resource.Issuer;
            var resourceContext = (JsonObject)resource.Payload.DeepClone();
            var requestedScope = (string?)resource.Payload["scope"] is { } scopeClaim && !string.IsNullOrWhiteSpace(scopeClaim)
                ? scopeClaim : options.DefaultScope;

            IReadOnlyList<TokenRegistration> sourceRegistrations = [.. issuance.SourceTokens, TokenRegistration.FromVerified(presented, TokenCredential.Presented)];
            IReadOnlyList<TokenKey> sourceTokens;
            try
            {
                sourceTokens = await TokenRegistration.RegisterAsync(inventory, sourceRegistrations, ctx.RequestAborted);
            }
            catch (TokenVerificationException ex) { return AAuthProblemDetails.SourceRevoked(ex); }

            var policyClaims = options.DeriveAgentClaims?.Invoke(agentId);
            AccessDecision decision;
            try
            {
                decision = await policy.EvaluateAsync(new AccessPolicyRequest
                {
                    ResourceUrl = audience,
                    Scope = requestedScope,
                    AgentId = agentId,
                    Claims = policyClaims,
                    ResourceContext = resourceContext,
                    PersonServerIssuer = personServer,
                    UpstreamAuthorization = issuance.Upstream,
                });
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("policy_unavailable", ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            if (InvalidClaimPolicy(decision))
                return AAuthProblemDetails.Create("policy_error", "Requested or projected claims contain protocol-owned names.", statusCode: StatusCodes.Status500InternalServerError);

            AccessPendingEntry Park(IReadOnlyList<string>? requiredClaims = null)
            {
                var entry = pending.Add(audience, requestedScope, agentId, agentConfirmationKey, agentTokenExpiresAt, policyClaims,
                    requiredClaims, ceiling);
                entry.OriginPersonServerHost = personServer;
                entry.UpstreamAuthorization = issuance.Upstream;
                entry.SourceTokens = sourceTokens;
                entry.OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt;
                entry.ResourceContext = resourceContext;
                return entry;
            }

            switch (decision.Kind)
            {
                case AccessDecisionKind.NeedsClarification:
                    {
                        var entry = Park();
                        SetClarification(entry, decision.Clarification!);
                        return Clarification202(ctx, entry);
                    }
                case AccessDecisionKind.Deny:
                    return AAuth.Server.AAuthProblemDetails.Create("denied", decision.Reason, statusCode: StatusCodes.Status403Forbidden);
                case AccessDecisionKind.NeedsPayment:
                    {
                        // §Payment Required: Location MUST be present.
                        if (string.IsNullOrWhiteSpace(decision.PaymentUrl))
                        {
                            return AAuth.Server.AAuthProblemDetails.Create("policy_error", "NeedsPayment requires a payment Location", statusCode: StatusCodes.Status500InternalServerError);
                        }
                        ctx.Response.Headers.Location = decision.PaymentUrl;
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        return AAuth.Server.AAuthProblemDetails.Create("payment_required", statusCode: StatusCodes.Status402PaymentRequired);
                    }
                case AccessDecisionKind.NeedsInteraction:
                    {
                        var entry = Park();
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers["Retry-After"] = "1";
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        ctx.Response.Headers[AAuthRequirementHeader.Name] =
                            Interaction.Format($"{issuer}{loginPath}", entry.Browser.Code, options.EgressPolicy);
                        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                    }
                case AccessDecisionKind.NeedsClaims:
                    {
                        var entry = Park(decision.RequiredClaims);
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers["Retry-After"] = "0";
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        ctx.Response.Headers[AAuthRequirementHeader.Name] =
                            $"requirement={ClaimsRequirement.RequirementType}";
                        return Results.Json(
                            new { status = "pending", required_claims = decision.RequiredClaims },
                            statusCode: StatusCodes.Status202Accepted);
                    }
                case AccessDecisionKind.Allow:
                default:
                    var (allowTenant, allowClaims) = (decision.Tenant, decision.AdditionalClaims);
                    return await AuthTokenResponse.CreateTrackedAsync(ct => Mint(ct,
                            audience, requestedScope, agentConfirmationKey, resourceContext,
                            allowTenant, allowClaims, agentTokenExpiresAt, ceiling), ceiling,
                            inventory, sourceRegistrations, "auth_token", options.TimeProvider, ctx.RequestAborted);
            }
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the PS polls the deferred verdict.
        // -------------------------------------------------------------------
        routes.MapGet($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return DeferredState.Missing(id);
            }

            if (await AuthorizePsCallerAsync(ctx, entry) is { } pollFailure)
            {
                return pollFailure;
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                // A pending request started against a resource token its resource then
                // withdrew terminates with polling error `revoked` (#token-revocation).
                if (entry.ResourceContext is { } pendingResource
                    && await inventory.IsRevokedAsync(TokenRegistration.FromPayload(pendingResource).Token, ctx.RequestAborted))
                    return AAuthProblemDetails.Create("revoked", "The resource token was revoked.", statusCode: StatusCodes.Status403Forbidden);
                if (entry.Status == AccessPendingStatus.Review)
                {
                    var review = await EvaluatePendingAsync(entry, ctx);
                    if (review is not null) return review;
                }
                switch (entry.Status)
                {
                    case AccessPendingStatus.AwaitingClarification:
                        return Clarification202(ctx, entry);
                    case AccessPendingStatus.Allowed:
                        {
                            if (entry.RequiredClaims?.Any(name => !AuthTokenBuilder.IsIdentityClaimAllowed(name)) == true)
                                return AAuthProblemDetails.Create("policy_error", "Requested claims contain protocol-owned names.", statusCode: StatusCodes.Status500InternalServerError);
                            var (tenant, roles, groups, claims) = ProjectIdentityClaims(entry.SuppliedClaims, entry.RequiredClaims);
                            return await AuthTokenResponse.CreateTrackedAsync(ct => Mint(ct,
                                    entry.ResourceUrl, entry.Scope, entry.AgentConfirmationKey, entry.ResourceContext!,
                                    tenant, claims, entry.AgentTokenExpiresAt,
                                    entry.AuthorizationExpiresAt, roles, groups), entry.ExpiresAt,
                                    inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
                        }
                    case AccessPendingStatus.Denied:
                        return AAuth.Server.AAuthProblemDetails.Create("denied", entry.DenyReason, statusCode: StatusCodes.Status403Forbidden);
                    case AccessPendingStatus.Pending:
                    default:
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers["Retry-After"] = "1";
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        if (entry.RequiredClaims is { Count: > 0 } && entry.SuppliedClaims is null)
                        {
                            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                                $"requirement={ClaimsRequirement.RequirementType}";
                            return Results.Json(
                                new { status = "pending", required_claims = entry.RequiredClaims },
                                statusCode: StatusCodes.Status202Accepted);
                        }
                        ctx.Response.Headers[AAuthRequirementHeader.Name] =
                            Interaction.Format($"{issuer}{loginPath}", entry.Browser.Code, options.EgressPolicy);
                        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                }
            });
        });

        // -------------------------------------------------------------------
        // POST {PendingPathPrefix}/{id} — the §Claims Required push. The PS
        // POSTs (signed) the requested identity claims; never `sub`.
        // -------------------------------------------------------------------
        routes.MapPost($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return DeferredState.Missing(id);
            }

            if (await AuthorizePsCallerAsync(ctx, entry) is { } pushFailure)
            {
                return pushFailure;
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                JsonObject pushed;
                try
                {
                    pushed = await TokenRequestBody.ReadJsonAsync(ctx.Request);
                }
                catch (System.Text.Json.JsonException)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
                }
                if (entry.Status == AccessPendingStatus.AwaitingClarification)
                {
                    var action = StringMember(pushed, "action");
                    var answer = StringMember(pushed, "clarification_response");
                    var replacementJwt = StringMember(pushed, "resource_token");
                    var replacementPresentedJwt = StringMember(pushed, "presented_token");
                    if (action is not ("clarification_response" or "updated_request")
                        || (action == "clarification_response" && (string.IsNullOrWhiteSpace(answer) || pushed!.ContainsKey("resource_token")))
                        || (action == "updated_request" && (replacementJwt is null || replacementPresentedJwt is null
                            || pushed!.ContainsKey("clarification_response")))
                        || (pushed!.ContainsKey("justification") && StringMember(pushed, "justification") is null))
                        return AAuthProblemDetails.Create("invalid_request", "Expected matching clarification action and payload.", statusCode: StatusCodes.Status400BadRequest);
                    if (entry.ClarificationRounds >= AAuth.Agent.ClarificationExchange.DefaultMaxRounds)
                        return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: StatusCodes.Status403Forbidden);
                    if (action == "updated_request")
                    {
                        try { TokenRequestBody.ValidateCredentials(pushed, tokenVerifier); }
                        catch (System.Text.Json.JsonException)
                        {
                            return AAuthProblemDetails.Create("invalid_request", "body is not a valid token request", statusCode: StatusCodes.Status400BadRequest);
                        }
                        catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }
                        try
                        {
                            var replacement = await tokenVerifier.VerifyResourceTokenAsync(replacementJwt!, issuer,
                                entry.AgentConfirmationKey.ComputeJwkThumbprint(), metadataClient, jwksClient,
                                expectedPersonServer: entry.OriginPersonServerHost, cancellationToken: ctx.RequestAborted);
                            await tokenVerifier.VerifyPresentedTokenAsync(replacementPresentedJwt!, replacement,
                                metadataClient, jwksClient, ctx.RequestAborted);
                            TokenVerifier.RequireSameResourceRequest(entry.ResourceContext!, replacement.Payload);
                            if (!AccountBinding.Matches(entry.Account, replacement.Account))
                                throw new TokenVerificationException("Changing account requires a new authorization request.");
                            entry.Scope = (string?)replacement.Payload["scope"] ?? options.DefaultScope;
                            entry.ResourceContext = (JsonObject)replacement.Payload.DeepClone();
                        }
                        catch (TokenVerificationException ex)
                        {
                            return AAuthProblemDetails.TokenFailure(ex, TokenCredential.Resource);
                        }
                    }
                    entry.ClarificationRounds++;
                    if (answer is not null) entry.ClarificationAnswers.Add(answer);
                    if (StringMember(pushed, "justification") is { } justification) entry.ClarificationAnswers.Add(justification);
                    entry.Clarification = null;
                    entry.ClarificationDeadline = null;
                    entry.Status = AccessPendingStatus.Review;
                    return Results.NoContent();
                }
                if (entry.Status != AccessPendingStatus.Pending || entry.RequiredClaims is not { Count: > 0 })
                    return AAuthProblemDetails.Create("invalid_request", "No claims push is pending.", statusCode: StatusCodes.Status400BadRequest);

                if (pushed!.Any(claim => !AuthTokenBuilder.IsIdentityClaimAllowed(claim.Key)))
                    return AAuthProblemDetails.Create("invalid_request", "Pushed claims contain protocol-owned names (including sub).", statusCode: StatusCodes.Status400BadRequest);

                if (pushed.ContainsKey("tenant") && StringMember(pushed, "tenant") is null)
                    return AAuthProblemDetails.Create("invalid_request", "tenant must be a string.");
                foreach (var name in new[] { "roles", "groups" })
                    if (pushed.ContainsKey(name) && (pushed[name] is not JsonArray values
                        || values.Any(value => value is not JsonValue item || !item.TryGetValue<string>(out _))))
                        return AAuthProblemDetails.Create("invalid_request", $"{name} must be an array of strings.");

                entry.SuppliedClaims = pushed;

                var merged = entry.Claims is null ? new JsonObject() : (JsonObject)entry.Claims.DeepClone();
                foreach (var (k, v) in pushed!)
                {
                    merged[k] = v?.DeepClone();
                }

                AccessDecision decision;
                try
                {
                    decision = await policy.EvaluateAsync(new AccessPolicyRequest
                    {
                        ResourceUrl = entry.ResourceUrl,
                        Scope = entry.Scope,
                        AgentId = entry.AgentId,
                        Claims = merged,
                        InteractionId = entry.Id,
                        ClarificationHistory = entry.ClarificationAnswers,
                        ResourceContext = entry.ResourceContext,
                        PersonServerIssuer = entry.OriginPersonServerHost,
                        UpstreamAuthorization = entry.UpstreamAuthorization,
                    });
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("policy_unavailable", ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                if (InvalidClaimPolicy(decision))
                    return AAuthProblemDetails.Create("policy_error", "Requested or projected claims contain protocol-owned names.", statusCode: StatusCodes.Status500InternalServerError);

                switch (decision.Kind)
                {
                    case AccessDecisionKind.Allow:
                        {
                            entry.Status = AccessPendingStatus.Allowed;
                            var (tenant, roles, groups, claims) = ProjectIdentityClaims(pushed, entry.RequiredClaims);
                            return await AuthTokenResponse.CreateTrackedAsync(ct => Mint(ct,
                                    entry.ResourceUrl, entry.Scope, entry.AgentConfirmationKey, entry.ResourceContext!,
                                    tenant, claims, entry.AgentTokenExpiresAt,
                                    entry.AuthorizationExpiresAt, roles, groups), entry.ExpiresAt,
                                    inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
                        }
                    case AccessDecisionKind.Deny:
                        entry.Status = AccessPendingStatus.Denied;
                        entry.DenyReason = decision.Reason ?? "access denied";
                        return AAuth.Server.AAuthProblemDetails.Create("denied", decision.Reason, statusCode: StatusCodes.Status403Forbidden);
                    case AccessDecisionKind.NeedsClarification:
                        SetClarification(entry, decision.Clarification!);
                        return Clarification202(ctx, entry);
                    case AccessDecisionKind.NeedsInteraction:
                        entry.RequiredClaims = null;
                        entry.Browser.Renew();
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers.RetryAfter = "1";
                        ctx.Response.Headers[AAuthRequirementHeader.Name] = Interaction.Format($"{issuer}{loginPath}", entry.Browser.Code, options.EgressPolicy);
                        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                    case AccessDecisionKind.NeedsClaims:
                    default:
                        entry.RequiredClaims = decision.RequiredClaims ?? entry.RequiredClaims;
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers["Retry-After"] = "0";
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        ctx.Response.Headers[AAuthRequirementHeader.Name] =
                            $"requirement={ClaimsRequirement.RequirementType}";
                        return Results.Json(
                            new { status = "pending", required_claims = decision.RequiredClaims ?? entry.RequiredClaims },
                            statusCode: StatusCodes.Status202Accepted);
                }
            });
        });

        routes.MapDelete($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return DeferredState.Missing(id);
            if (await AuthorizePsCallerAsync(ctx, entry) is { } failure) return failure;
            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, () =>
            {
                entry.Lifecycle.Cancel();
                return Task.FromResult<IResult>(Results.NoContent());
            });
        });

        return app;

        void SetClarification(AccessPendingEntry entry, ClarificationRequirement clarification)
        {
            entry.Clarification = clarification;
            entry.ClarificationDeadline = options.TimeProvider.GetUtcNow().AddSeconds(clarification.TimeoutSeconds ?? 300);
            entry.Status = AccessPendingStatus.AwaitingClarification;
        }

        IResult Clarification202(HttpContext ctx, AccessPendingEntry entry)
        {
            ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
            ctx.Response.Headers.RetryAfter = "1";
            ctx.Response.Headers.CacheControl = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] = "requirement=clarification";
            var question = entry.Clarification!;
            var body = new JsonObject { ["clarification"] = question.Clarification };
            if (question.TimeoutSeconds is { } timeout) body["timeout"] = timeout;
            if (question.Options is { } choices) body["options"] = new JsonArray(choices.Select(choice => (JsonNode?)JsonValue.Create(choice)).ToArray());
            return Results.Json(body, statusCode: StatusCodes.Status202Accepted);
        }

        async Task<IResult?> EvaluatePendingAsync(AccessPendingEntry entry, HttpContext ctx)
        {
            var decision = await policy.EvaluateAsync(new AccessPolicyRequest
            {
                AgentId = entry.AgentId,
                ResourceUrl = entry.ResourceUrl,
                Scope = entry.Scope,
                Claims = entry.SuppliedClaims ?? entry.Claims,
                InteractionId = entry.Id,
                ClarificationHistory = entry.ClarificationAnswers,
                ResourceContext = entry.ResourceContext,
                PersonServerIssuer = entry.OriginPersonServerHost,
                UpstreamAuthorization = entry.UpstreamAuthorization,
            }, ctx.RequestAborted);
            if (InvalidClaimPolicy(decision)) return AAuthProblemDetails.Create("policy_error", statusCode: 500);
            switch (decision.Kind)
            {
                case AccessDecisionKind.Allow:
                    entry.Status = AccessPendingStatus.Allowed;
                    return await AuthTokenResponse.CreateTrackedAsync(ct => Mint(ct, entry.ResourceUrl, entry.Scope,
                        entry.AgentConfirmationKey, entry.ResourceContext!, decision.Tenant,
                        decision.AdditionalClaims, entry.AgentTokenExpiresAt, entry.AuthorizationExpiresAt),
                        entry.ExpiresAt, inventory, entry.SourceTokens, options.TimeProvider, ctx.RequestAborted);
                case AccessDecisionKind.Deny:
                    entry.Status = AccessPendingStatus.Denied;
                    entry.DenyReason = decision.Reason;
                    return AAuthProblemDetails.Create("denied", decision.Reason, statusCode: 403);
                case AccessDecisionKind.NeedsClarification:
                    if (entry.ClarificationRounds >= AAuth.Agent.ClarificationExchange.DefaultMaxRounds)
                        return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: 403);
                    SetClarification(entry, decision.Clarification!);
                    return Clarification202(ctx, entry);
                case AccessDecisionKind.NeedsPayment:
                    ctx.Response.Headers.Location = decision.PaymentUrl;
                    return AAuthProblemDetails.Create("payment_required", statusCode: 402);
                default:
                    entry.Status = AccessPendingStatus.Pending;
                    entry.RequiredClaims = decision.RequiredClaims;
                    if (decision.Kind == AccessDecisionKind.NeedsInteraction) entry.Browser.Renew();
                    return null;
            }
        }
    }

    private static string? StringMember(JsonObject? body, string name) =>
        body?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    // Project the pushed identity claims into (tenant, roles, groups, additional
    // claims). `sub` is never pushed; it is the resource token's.
    private static bool InvalidClaimPolicy(AccessDecision decision) =>
        decision.RequiredClaims?.Any(name => !AuthTokenBuilder.IsIdentityClaimAllowed(name)) == true
        || decision.AdditionalClaims?.Keys.Any(AuthTokenBuilder.IsReservedClaim) == true;

    private static (string? Tenant, IReadOnlyList<string>? Roles, IReadOnlyList<string>? Groups, IReadOnlyDictionary<string, JsonNode?>? Claims) ProjectIdentityClaims(
        JsonObject? pushed, IReadOnlyList<string>? requiredClaims)
    {
        if (pushed is null || requiredClaims is null || requiredClaims.Count == 0)
        {
            return (null, null, null, null);
        }

        string? tenant = null;
        IReadOnlyList<string>? roles = null;
        IReadOnlyList<string>? groups = null;
        var result = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var name in requiredClaims)
        {
            if (string.Equals(name, "sub", StringComparison.Ordinal))
            {
                continue;
            }
            if (pushed[name] is not { } node)
            {
                continue;
            }
            if (string.Equals(name, "tenant", StringComparison.Ordinal))
            {
                tenant = (string?)node;
            }
            else if (name == "roles")
            {
                roles = node.AsArray().Select(value => value!.GetValue<string>()).ToArray();
            }
            else if (name == "groups")
            {
                groups = node.AsArray().Select(value => value!.GetValue<string>()).ToArray();
            }
            else if (!AuthTokenBuilder.IsReservedClaim(name))
            {
                result[name] = node.DeepClone();
            }
        }

        return (tenant, roles, groups, result.Count > 0 ? result : null);
    }
}
