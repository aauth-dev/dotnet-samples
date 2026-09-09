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
    public AAuthEgressPolicy EgressPolicy { get; init; } = AAuthEgressPolicy.Production;
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>HTTPS URL of this Access Server (<c>iss</c> of minted auth tokens).</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The AS signing keys, keyed by <c>kid</c>. Published at the JWKS and used
    /// to sign minted auth tokens (the first entry signs).
    /// </summary>
    public required IReadOnlyDictionary<string, IAAuthKey> SigningKeys { get; init; }

    /// <summary>The token endpoint path. Default <c>/token</c>.</summary>
    public string TokenPath { get; init; } = "/token";
    public string RevocationPath { get; init; } = "/revoke";
    public Action<AAuthRevocationOptions>? ConfigureRevocation { get; init; }

    /// <summary>The pending (poll/push) path prefix. Default <c>/pending</c>.</summary>
    public string PendingPathPrefix { get; init; } = "/pending";

    /// <summary>
    /// The fallback scope when the resource token carries none. Default empty:
    /// the spec makes <c>scope</c> OPTIONAL, so a scopeless resource token mints
    /// a scopeless auth token (still valid via its <c>sub</c>) rather than
    /// injecting an arbitrary scope.
    /// </summary>
    public string DefaultScope { get; init; } = "";

    /// <summary>
    /// Person Server allow-list this AS will broker for, matched on the caller's
    /// <c>jwks_uri</c> host. <b>Open by default (spec-compliant):</b> when
    /// <c>null</c>, any validly-signed PS is brokered — §PS-AS Trust Establishment
    /// requires no separate registration step. An <b>empty</b> set denies all; a
    /// non-empty set restricts (pre-established trust). Composed by AND with
    /// <see cref="IsTrustedPersonServer"/>.
    /// </summary>
    public IReadOnlyCollection<string>? TrustedPersonServers { get; init; }

    /// <summary>
    /// Optional trust policy for Person Servers, evaluated per caller
    /// <c>jwks_uri</c> host and composed by AND with
    /// <see cref="TrustedPersonServers"/>. <c>null</c> ⇒ no policy constraint.
    /// Assign <see cref="AAuth.Server.AAuthTrust.Any"/> to state intentional open
    /// trust explicitly.
    /// </summary>
    public Func<string, bool>? IsTrustedPersonServer { get; init; }

    /// <summary>
    /// Optional hook deriving baseline policy claims from the verified agent id
    /// (e.g. a demo admin-role convention). A production AS receives the
    /// principal's claims via the §Claims Required push instead.
    /// </summary>
    public Func<string, JsonObject?>? DeriveAgentClaims { get; init; }

    /// <summary>
    /// The AS-hosted login path advertised on <c>requirement=interaction</c>.
    /// Default <c>/interaction/login</c>. The caller maps this endpoint and
    /// resolves the verdict against the shared <see cref="IAccessPendingStore"/>.
    /// </summary>
    public string InteractionLoginPath { get; init; } = "/interaction/login";
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
    public static WebApplication MapAAuthAccessServer(
        this WebApplication app,
        AAuthAccessServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        if (options.SigningKeys.Count == 0)
        {
            throw new InvalidOperationException("AAuthAccessServerOptions.SigningKeys must contain at least one key.");
        }

        // Fail fast on misconfigured spec-constrained URLs/paths: the issuer is the
        // auth-token `iss`/`aud` anchor (MUST be absolute https), the login path is
        // appended with `?code=…` (so it carries no query/fragment), and each trusted
        // Person Server is a four-party anchor (MUST be absolute https).
        if (!AAuth.AAuthUrl.IsHttpsOrLoopback(options.Issuer, options.EgressPolicy))
        {
            throw new InvalidOperationException(
                "AAuthAccessServerOptions.Issuer must be an absolute https URL (loopback http allowed for development).");
        }
        if (options.InteractionLoginPath is { } loginPathRaw
            && (loginPathRaw.Contains('?') || loginPathRaw.Contains('#')))
        {
            throw new InvalidOperationException(
                "AAuthAccessServerOptions.InteractionLoginPath must not contain a query or fragment.");
        }
        foreach (var trustedPs in options.TrustedPersonServers ?? Array.Empty<string>())
        {
            if (!AAuth.AAuthUrl.IsHttpsOrLoopback(trustedPs, options.EgressPolicy))
            {
                throw new InvalidOperationException(
                    $"AAuthAccessServerOptions.TrustedPersonServers entry '{trustedPs}' must be an absolute https URL " +
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
        var inventory = app.MapAAuthIssuerRevocation(issuer, AuthTokenBuilder.AccessDwk,
            signingKey, signingKid, options.RevocationPath, options.EgressPolicy, options.TimeProvider, options.ConfigureRevocation);
        var loginPath = "/" + options.InteractionLoginPath.Trim('/');
        var interactionPrefix = loginPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : loginPath;

        var trustedPsHosts = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ps in options.TrustedPersonServers ?? Array.Empty<string>())
        {
            if (Uri.TryCreate(ps, UriKind.Absolute, out var psUri))
            {
                trustedPsHosts.Add(ps);
            }
        }

        // Preserve null (open: broker any verifiable PS) vs. empty (deny all). The
        // host set drives membership; the nullable form drives the open/empty split.
        IReadOnlyCollection<string>? trustedPsHostsOrNull =
            options.TrustedPersonServers is null ? null : trustedPsHosts;

        // Startup footgun guard (diagnostics only): warn when brokering is open by
        // default. Suppressed by any explicit policy (including AAuthTrust.Any).
        TrustConfigDiagnostics.WarnIfOpenFederation(
            app.Services.GetService<ILoggerFactory>()?.CreateLogger("AAuth.AccessServer"),
            trustConfigured: options.TrustedPersonServers is not null || options.IsTrustedPersonServer is not null,
            "MapAAuthAccessServer",
            "this Access Server brokers for any verifiable Person Server because no TrustedPersonServers / " +
            "IsTrustedPersonServer policy is configured (the AAuth spec default). Configure a policy to " +
            "restrict, or assign AAuthTrust.Any to declare intentional open brokering and silence this warning.");

        // 1. Well-known metadata + JWKS (reachable without a signature).
        WellKnownEndpoints.MapAAuthAccessServerWellKnown(app, new AAuthAccessServerMetadataOptions
        {
            EgressPolicy = options.EgressPolicy,
            Issuer = options.Issuer,
            TokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = new Dictionary<string, IAAuthKey>(options.SigningKeys),
            RevocationEndpoint = $"{issuer}{options.RevocationPath}",
        });

        // 2. Verification middleware. The PS signs with the jwks_uri scheme
        //    with verified metadata discovery; the browser-facing interaction
        //    endpoints carry no signature, so exclude them.
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
                && ctx.Request.Path != options.RevocationPath
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix),
            branch => branch.UseAAuthVerification(new AAuthVerificationOptions { EgressPolicy = options.EgressPolicy, AcceptedSchemes = ["jwks_uri", "jwt"], Clock = () => options.TimeProvider.GetUtcNow() }));

        var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var policy = app.Services.GetRequiredService<IAccessPolicy>();
        var pending = app.Services.GetRequiredService<IAccessPendingStore>();

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
        IResult? AuthorizePsCaller(HttpContext c, AccessPendingEntry entry)
        {
            var parsedKey = c.GetAAuthParsedKey();
            if (entry.OwnerAgentIssuer is not null)
            {
                if (parsedKey?.Scheme != AAuthConstants.Schemes.Jwt
                    || c.GetAAuthTokenType() != AAuthTokenType.AgentToken
                    || (string?)parsedKey.Payload?["iss"] != entry.OwnerAgentIssuer
                    || (string?)parsedKey.Payload?["sub"] != entry.OwnerAgentSubject
                    || c.GetAAuthVerification()?.Jkt != entry.OwnerKeyThumbprint)
                    return AAuthProblemDetails.Create("unknown_interaction", statusCode: 403);
                return null;
            }
            if (parsedKey is null || parsedKey.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_carrier", "expected jwks_uri scheme", statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!IsVerifiedPersonServer(c))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "A verified Person Server metadata role is required.", statusCode: StatusCodes.Status403Forbidden);
            }

            if (!IssuerTrust.IsTrusted(trustedPsHostsOrNull, options.IsTrustedPersonServer, parsedKey.Identifier!))
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

        string Mint(
            string resourceUrl, string agentId, string scope, IAAuthKey confirmationKey,
            string? subject, string? tenant, IReadOnlyDictionary<string, JsonNode?>? additionalClaims,
            DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt = null,
            JsonObject? upstreamAct = null, IReadOnlyList<string>? roles = null, IReadOnlyList<string>? groups = null,
            JsonObject? resourceContext = null) =>
            new AuthTokenBuilder
            {
                EgressPolicy = options.EgressPolicy,
                Issuer = options.Issuer,
                Audience = resourceUrl,
                Agent = agentId,
                AgentConfirmationKey = confirmationKey,
                AgentTokenExpiresAt = agentTokenExpiresAt,
                AuthorizationExpiresAt = authorizationExpiresAt,
                TimeProvider = options.TimeProvider,
                Act = upstreamAct,
                Mission = resourceContext is null ? null : MissionClaim.FromPayload(resourceContext, options.EgressPolicy),
                Account = AccountBinding.Read(resourceContext),
                Key = signingKey,
                KeyId = signingKid,
                Subject = subject,
                Scope = scope,
                Tenant = tenant,
                Roles = roles,
                Groups = groups,
                Dwk = AuthTokenBuilder.AccessDwk,
                AdditionalClaims = additionalClaims,
            }.Build();

        // -------------------------------------------------------------------
        // POST {TokenPath} — the AS token endpoint (§AS Token Endpoint).
        // -------------------------------------------------------------------
        app.MapPost(options.TokenPath, async (HttpContext ctx) =>
        {
            var parsed = ctx.GetAAuthParsedKey()!;

            var direct = parsed.Scheme == AAuthConstants.Schemes.Jwt;
            if (direct && ctx.GetAAuthTokenType() != AAuthTokenType.AgentToken)
                return AAuthProblemDetails.Create("invalid_carrier_token", "Direct chaining requires the intermediary agent token.", statusCode: 403);
            if (!direct && parsed.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_carrier", $"expected jwks_uri scheme, got {parsed.Scheme}", statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!direct)
            {
                var jwksUri = parsed.Identifier;
                if (!IsVerifiedPersonServer(ctx))
                {
                    return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", "A verified Person Server metadata role is required.", statusCode: StatusCodes.Status403Forbidden);
                }
                if (!IssuerTrust.IsTrusted(trustedPsHostsOrNull, options.IsTrustedPersonServer, jwksUri!))
                {
                    return AAuth.Server.AAuthProblemDetails.Create("untrusted_person_server", $"jwks_uri '{jwksUri}' is not a trusted Person Server", statusCode: StatusCodes.Status403Forbidden);
                }
            }

            // The PS host that signs this /token call owns any pending entry we
            // park below; the pending poll/push endpoints re-pin to it (F2).
            var originPsHost = direct ? null : parsed.Identifier;

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

            if (direct && body?["agent_token"] is not null)
                return AAuthProblemDetails.Create("invalid_request", "Direct chaining takes its agent token only from Signature-Key.", statusCode: 400);
            if (direct && string.IsNullOrEmpty(StringMember(body, "upstream_token")))
                return AAuthProblemDetails.Create("invalid_request", "Direct chaining requires upstream_token.", statusCode: 400);
            var agentTokenJwt = direct ? parsed.Jwt : (string?)body?["agent_token"];
            if (string.IsNullOrEmpty(agentTokenJwt))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing agent_token", statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceTokenJwt = (string?)body?["resource_token"];
            if (string.IsNullOrEmpty(resourceTokenJwt))
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing resource_token", statusCode: StatusCodes.Status400BadRequest);
            }

            // Verify the agent token; extract the agent id + confirmation key.
            AgentIssuanceContext issuance;
            IReadOnlyList<TokenKey> sourceTokens;
            try
            {
                issuance = await AgentIssuanceContext.VerifyAsync(
                    agentTokenJwt, (string?)body?["subagent_token"], (string?)body?["upstream_token"],
                    tokenVerifier, metadataClient, jwksClient,
                    upstreamIssuer => string.Equals(upstreamIssuer, issuer, StringComparison.Ordinal)
                        || string.Equals(upstreamIssuer, parsed.Identifier, StringComparison.Ordinal),
                    ctx.RequestAborted);
                if (direct && (issuance.Upstream?.Issuer != issuer
                    || issuance.Upstream.IssuerDwk != AuthTokenBuilder.AccessDwk || issuance.Upstream.Mission is not null))
                    throw new TokenVerificationException("Direct AS chaining requires this AS's no-mission upstream authorization.");
            }
            catch (TokenVerificationException ex)
            {
                return AAuthProblemDetails.TokenFailure(ex);
            }

            var agentId = issuance.AgentId;
            var agentConfirmationKey = issuance.ConfirmationKey;
            var agentTokenExpiresAt = issuance.AgentTokenExpiresAt;

            // Verify the resource token. `aud` MUST be this AS; `iss` becomes
            // the auth token's `aud` and `scope` is echoed.
            string audience;
            JsonObject resourceContext;
            var requestedScope = options.DefaultScope;
            try
            {
                var verifiedResourceToken = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: options.Issuer,
                    expectedAgentId: agentId,
                    expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
                    metadataClient, jwksClient, expectedApprover: originPsHost);

                audience = (string?)verifiedResourceToken.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                resourceContext = (JsonObject)verifiedResourceToken.Payload.DeepClone();
                issuance.ValidateResourceContext(resourceContext, originPsHost);
                if (direct && resourceContext["mission"] is not null)
                    throw new TokenVerificationException("Mission authorization must be routed through its governing PS.");
                var scopeClaim = (string?)verifiedResourceToken.Payload["scope"];
                if (!string.IsNullOrWhiteSpace(scopeClaim))
                {
                    requestedScope = scopeClaim;
                }
            }
            catch (TokenVerificationException ex)
            {
                var expired = ex.Code == AAuth.Errors.SignatureErrorCode.ExpiredJwt;
                // §Token Endpoint Error Codes: invalid_resource_token / expired_resource_token
                // are 400 (a bad token parameter in the body), not 401 — 401 is reserved for
                // request-signature failures carrying a Signature-Error header (§Authentication
                // Errors). The request itself was correctly signed; the resource_token is invalid.
                return AAuth.Server.AAuthProblemDetails.Create(expired ? "expired_resource_token" : "invalid_resource_token", ex.Message, statusCode: StatusCodes.Status400BadRequest);
            }

            try { sourceTokens = await TokenRegistration.RegisterAsync(inventory, issuance.SourceTokens, ctx.RequestAborted); }
            catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }

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
                    PersonServerIssuer = originPsHost,
                    UpstreamAuthorization = issuance.Upstream,
                });
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("policy_unavailable", ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            if (InvalidClaimPolicy(decision))
                return AAuthProblemDetails.Create("policy_error", "Requested or projected claims contain protocol-owned names.", statusCode: StatusCodes.Status500InternalServerError);

            if (direct && decision.Kind == AccessDecisionKind.NeedsClaims)
                return AAuthProblemDetails.Create("denied", "An intermediary cannot assert PS identity claims.", statusCode: 403);

            void BindOwner(AccessPendingEntry entry)
            {
                entry.OriginPersonServerHost = originPsHost;
                entry.OwnerAgentIssuer = direct ? (string?)parsed.Payload?["iss"] : null;
                entry.OwnerAgentSubject = direct ? (string?)parsed.Payload?["sub"] : null;
            }

            switch (decision.Kind)
            {
                case AccessDecisionKind.NeedsClarification:
                    {
                        var entry = pending.Add(audience, requestedScope, agentId, agentConfirmationKey, agentTokenExpiresAt, policyClaims,
                            authorizationExpiresAt: issuance.ExpiresAt, upstreamAct: issuance.Act);
                        BindOwner(entry);
                        entry.UpstreamAuthorization = issuance.Upstream;
                        entry.SourceTokens = sourceTokens;
                        entry.OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt;
                        entry.ResourceContext = resourceContext;
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
                        var entry = pending.Add(audience, requestedScope, agentId, agentConfirmationKey, agentTokenExpiresAt, policyClaims,
                            authorizationExpiresAt: issuance.ExpiresAt, upstreamAct: issuance.Act);
                        BindOwner(entry);
                        entry.UpstreamAuthorization = issuance.Upstream;
                        entry.SourceTokens = sourceTokens;
                        entry.OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt;
                        entry.ResourceContext = resourceContext;
                        ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                        ctx.Response.Headers["Retry-After"] = "1";
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        ctx.Response.Headers[AAuthRequirementHeader.Name] =
                            Interaction.Format($"{issuer}{loginPath}", entry.Browser.Code, options.EgressPolicy);
                        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                    }
                case AccessDecisionKind.NeedsClaims:
                    {
                        var entry = pending.Add(
                            audience, requestedScope, agentId, agentConfirmationKey, agentTokenExpiresAt, policyClaims, decision.RequiredClaims,
                            issuance.ExpiresAt, issuance.Act);
                        BindOwner(entry);
                        entry.UpstreamAuthorization = issuance.Upstream;
                        entry.SourceTokens = sourceTokens;
                        entry.OwnerKeyThumbprint = ctx.GetAAuthVerification()!.Jkt;
                        entry.ResourceContext = resourceContext;
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
                    return await AuthTokenResponse.CreateTrackedAsync(() => Mint(
                            audience, agentId, requestedScope, agentConfirmationKey,
                            decision.Subject, allowTenant, allowClaims, agentTokenExpiresAt,
                            issuance.ExpiresAt, issuance.Act, resourceContext: resourceContext), issuance.ExpiresAt,
                            inventory, sourceTokens, options.TimeProvider, ctx.RequestAborted);
            }
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the PS polls the deferred verdict.
        // -------------------------------------------------------------------
        app.MapGet($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return DeferredState.Missing(id);
            }

            if (AuthorizePsCaller(ctx, entry) is { } pollFailure)
            {
                return pollFailure;
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
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
                            return await AuthTokenResponse.CreateTrackedAsync(() => Mint(
                                    entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey,
                                    entry.SuppliedSubject, tenant, claims, entry.AgentTokenExpiresAt,
                                    entry.AuthorizationExpiresAt, entry.UpstreamAct, roles, groups, entry.ResourceContext), entry.ExpiresAt,
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
        // POSTs (signed) the requested identity claims incl. a directed `sub`.
        // -------------------------------------------------------------------
        app.MapPost($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return DeferredState.Missing(id);
            }

            if (AuthorizePsCaller(ctx, entry) is { } pushFailure)
            {
                return pushFailure;
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.PendingExpiresAt, options.TimeProvider, async () =>
            {
                JsonObject? pushed;
                try
                {
                    pushed = await TokenRequestBody.ReadAsync(ctx.Request, tokenVerifier);
                }
                catch (System.Text.Json.JsonException)
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
                }
                catch (TokenVerificationException ex) { return AAuthProblemDetails.TokenFailure(ex); }

                if (entry.Status == AccessPendingStatus.AwaitingClarification || pushed?.ContainsKey("action") == true)
                {
                    var action = StringMember(pushed, "action");
                    var answer = StringMember(pushed, "clarification_response");
                    var replacementJwt = StringMember(pushed, "resource_token");
                    if (entry.Status != AccessPendingStatus.AwaitingClarification
                        || action is not ("clarification_response" or "updated_request")
                        || (action == "clarification_response" && (string.IsNullOrWhiteSpace(answer) || pushed!.ContainsKey("resource_token")))
                        || (action == "updated_request" && (string.IsNullOrWhiteSpace(replacementJwt) || pushed!.ContainsKey("clarification_response")))
                        || (pushed!.ContainsKey("justification") && StringMember(pushed, "justification") is null))
                        return AAuthProblemDetails.Create("invalid_request", "Expected matching clarification action and payload.", statusCode: StatusCodes.Status400BadRequest);
                    if (entry.ClarificationRounds >= AAuth.Agent.ClarificationExchange.DefaultMaxRounds)
                        return AAuthProblemDetails.Create("denied", "Clarification round limit reached.", statusCode: StatusCodes.Status403Forbidden);
                    if (action == "updated_request")
                    {
                        try
                        {
                            var replacement = await tokenVerifier.VerifyResourceTokenAsync(replacementJwt!, issuer, entry.AgentId,
                                entry.AgentConfirmationKey.ComputeJwkThumbprint(), metadataClient, jwksClient,
                                expectedApprover: entry.OriginPersonServerHost);
                            if (!string.Equals((string?)replacement.Payload["iss"], entry.ResourceUrl, StringComparison.Ordinal))
                                throw new TokenVerificationException("Replacement resource issuer differs from original.");
                            if (!AccountBinding.Matches(entry.Account, replacement.Account))
                                throw new TokenVerificationException("Changing account requires a new authorization request.");
                            var replacementMission = MissionClaim.FromPayload(replacement.Payload, options.EgressPolicy);
                            if (entry.OwnerAgentIssuer is not null && replacementMission is not null)
                                throw new TokenVerificationException("Mission authorization requires its governing PS.");
                            if (entry.UpstreamAuthorization?.Mission is { } upstreamMission
                                && (replacementMission?.Approver != upstreamMission.Approver || replacementMission.S256 != upstreamMission.S256))
                                throw new TokenVerificationException("Replacement must retain its upstream mission.");
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
                if (entry.OwnerAgentIssuer is not null)
                    return AAuthProblemDetails.Create("denied", "An intermediary cannot assert PS identity claims.", statusCode: 403);

                var directedSub = StringMember(pushed, "sub");
                if (string.IsNullOrEmpty(directedSub))
                {
                    return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing directed sub", statusCode: StatusCodes.Status400BadRequest);
                }

                if (pushed!.Any(claim => !AuthTokenBuilder.IsIdentityClaimAllowed(claim.Key)))
                    return AAuthProblemDetails.Create("invalid_request", "Pushed claims contain protocol-owned names.", statusCode: StatusCodes.Status400BadRequest);

                entry.SuppliedSubject = directedSub;
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
                            return await AuthTokenResponse.CreateTrackedAsync(() => Mint(
                                    entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey,
                                    directedSub, tenant, claims, entry.AgentTokenExpiresAt,
                                    entry.AuthorizationExpiresAt, entry.UpstreamAct, roles, groups, entry.ResourceContext), entry.ExpiresAt,
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

        app.MapDelete($"{options.PendingPathPrefix}/{{id}}", async (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return DeferredState.Missing(id);
            if (AuthorizePsCaller(ctx, entry) is { } failure) return failure;
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
            if (entry.OwnerAgentIssuer is not null && decision.Kind == AccessDecisionKind.NeedsClaims)
                return AAuthProblemDetails.Create("denied", "An intermediary cannot assert PS identity claims.", statusCode: 403);
            switch (decision.Kind)
            {
                case AccessDecisionKind.Allow:
                    entry.Status = AccessPendingStatus.Allowed;
                    return await AuthTokenResponse.CreateTrackedAsync(() => Mint(entry.ResourceUrl, entry.AgentId, entry.Scope,
                        entry.AgentConfirmationKey, decision.Subject ?? entry.SuppliedSubject, decision.Tenant,
                        decision.AdditionalClaims, entry.AgentTokenExpiresAt, entry.AuthorizationExpiresAt, entry.UpstreamAct, resourceContext: entry.ResourceContext),
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

    // Project the pushed identity claims into (tenant, additional claims). The
    // directed `sub` is emitted separately as the token's `sub`; `tenant` is a
    // first-class named claim (§Auth Token), the rest are additional claims.
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
