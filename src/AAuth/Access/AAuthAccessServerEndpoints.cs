using System;
using System.Collections.Generic;
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
    /// <summary>HTTPS URL of this Access Server (<c>iss</c> of minted auth tokens).</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The AS signing keys, keyed by <c>kid</c>. Published at the JWKS and used
    /// to sign minted auth tokens (the first entry signs).
    /// </summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>The token endpoint path. Default <c>/token</c>.</summary>
    public string TokenPath { get; init; } = "/token";

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
    /// The fallback directed <c>sub</c> when neither the policy nor a claims
    /// push supplies one. Default <c>pairwise-sub</c>.
    /// </summary>
    public string FallbackSubject { get; init; } = "pairwise-sub";

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
        if (!AAuth.AAuthUrl.IsHttpsOrLoopback(options.Issuer))
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
            if (!AAuth.AAuthUrl.IsHttpsOrLoopback(trustedPs))
            {
                throw new InvalidOperationException(
                    $"AAuthAccessServerOptions.TrustedPersonServers entry '{trustedPs}' must be an absolute https URL " +
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
        var loginPath = "/" + options.InteractionLoginPath.Trim('/');
        var interactionPrefix = loginPath.Split('/', StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } seg
            ? "/" + seg[0]
            : loginPath;

        var trustedPsHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ps in options.TrustedPersonServers ?? Array.Empty<string>())
        {
            if (Uri.TryCreate(ps, UriKind.Absolute, out var psUri))
            {
                trustedPsHosts.Add(psUri.Authority);
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
            Issuer = options.Issuer,
            TokenEndpoint = $"{issuer}{options.TokenPath}",
            SigningKeys = new Dictionary<string, AAuthKey>(options.SigningKeys),
        });

        // 2. Verification middleware. The PS signs with the jwks_uri scheme
        //    (RequireIssuerVerification=false); the browser-facing interaction
        //    endpoints carry no signature, so exclude them.
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
                && !ctx.Request.Path.StartsWithSegments(interactionPrefix),
            branch => branch.UseAAuthVerification(AAuthVerificationOptions.SignatureOnly()));

        var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
        var metadataClient = app.Services.GetRequiredService<MetadataClient>();
        var jwksClient = app.Services.GetRequiredService<JwksClient>();
        var policy = app.Services.GetRequiredService<IAccessPolicy>();
        var pending = app.Services.GetRequiredService<IAccessPendingStore>();

        // Re-pin a pending poll/push caller: it MUST present the jwks_uri
        // scheme, its host MUST be trusted (when a trust set is configured),
        // and it MUST be the same Person Server that parked the entry. Returns
        // a failure result, or null when authorized.
        IResult? AuthorizePsCaller(HttpContext c, AccessPendingEntry entry)
        {
            var parsedKey = c.GetAAuthParsedKey();
            if (parsedKey is null || parsedKey.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return Results.Json(
                    new { error = "invalid_carrier", detail = "expected jwks_uri scheme" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            if (string.IsNullOrEmpty(parsedKey.JwksUri)
                || !Uri.TryCreate(parsedKey.JwksUri, UriKind.Absolute, out var callerUri))
            {
                return Results.Json(
                    new { error = "untrusted_person_server", detail = "missing or invalid jwks_uri" },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            if (!IssuerTrust.IsTrusted(trustedPsHostsOrNull, options.IsTrustedPersonServer, callerUri.Authority))
            {
                return Results.Json(
                    new { error = "untrusted_person_server", detail = $"jwks_uri '{parsedKey.JwksUri}' is not a trusted Person Server" },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            if (entry.OriginPersonServerHost is { Length: > 0 } origin
                && !string.Equals(origin, callerUri.Authority, StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(
                    new { error = "untrusted_person_server", detail = "pending entry belongs to a different Person Server" },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            return null;
        }

        string Mint(
            string resourceUrl, string agentId, string scope, IAAuthKey confirmationKey,
            string? subject, string? tenant, IReadOnlyDictionary<string, JsonNode?>? additionalClaims) =>
            new AuthTokenBuilder
            {
                Issuer = options.Issuer,
                Audience = resourceUrl,
                Agent = agentId,
                AgentConfirmationKey = confirmationKey,
                Key = signingKey,
                KeyId = signingKid,
                Subject = subject ?? options.FallbackSubject,
                Scope = scope,
                Tenant = tenant,
                Dwk = AuthTokenBuilder.AccessDwk,
                AdditionalClaims = additionalClaims,
            }.Build();

        // -------------------------------------------------------------------
        // POST {TokenPath} — the AS token endpoint (§AS Token Endpoint).
        // -------------------------------------------------------------------
        app.MapPost(options.TokenPath, async (HttpContext ctx) =>
        {
            var parsed = ctx.GetAAuthParsedKey()!;

            if (parsed.Scheme != AAuthConstants.Schemes.JwksUri)
            {
                return Results.Json(
                    new { error = "invalid_carrier", detail = $"expected jwks_uri scheme, got {parsed.Scheme}" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            {
                var jwksUri = parsed.JwksUri;
                var callerAuthority = Uri.TryCreate(jwksUri, UriKind.Absolute, out var psUri)
                    ? psUri.Authority
                    : string.Empty;
                if (!IssuerTrust.IsTrusted(trustedPsHostsOrNull, options.IsTrustedPersonServer, callerAuthority))
                {
                    return Results.Json(
                        new { error = "untrusted_person_server", detail = $"jwks_uri '{jwksUri}' is not a trusted Person Server" },
                        statusCode: StatusCodes.Status403Forbidden);
                }
            }

            // The PS host that signs this /token call owns any pending entry we
            // park below; the pending poll/push endpoints re-pin to it (F2).
            var originPsHost = Uri.TryCreate(parsed.JwksUri, UriKind.Absolute, out var originUri)
                ? originUri.Authority
                : null;

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

            var agentTokenJwt = (string?)body?["agent_token"];
            if (string.IsNullOrEmpty(agentTokenJwt))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing agent_token" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceTokenJwt = (string?)body?["resource_token"];
            if (string.IsNullOrEmpty(resourceTokenJwt))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing resource_token" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            // Verify the agent token; extract the agent id + confirmation key.
            string agentId;
            AAuthKey agentConfirmationKey;
            try
            {
                var verifiedAgentToken = await tokenVerifier.VerifyWithJwksAsync(
                    agentTokenJwt, metadataClient, jwksClient,
                    AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null);

                agentId = (string?)verifiedAgentToken.Payload["sub"]
                    ?? throw new TokenVerificationException("agent_token missing sub");
                var cnfJwk = verifiedAgentToken.Payload["cnf"]?["jwk"] as JsonObject
                    ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
                agentConfirmationKey = AAuthKey.FromJwk(cnfJwk);
            }
            catch (TokenVerificationException ex)
            {
                return Results.Json(new { error = "invalid_agent_token", detail = ex.Message },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // Verify the resource token. `aud` MUST be this AS; `iss` becomes
            // the auth token's `aud` and `scope` is echoed.
            string audience;
            var requestedScope = options.DefaultScope;
            try
            {
                var verifiedResourceToken = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceTokenJwt,
                    expectedAudience: options.Issuer,
                    expectedAgentId: agentId,
                    expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
                    metadataClient, jwksClient);

                audience = (string?)verifiedResourceToken.Payload["iss"]
                    ?? throw new TokenVerificationException("resource_token missing iss");
                var scopeClaim = (string?)verifiedResourceToken.Payload["scope"];
                if (!string.IsNullOrWhiteSpace(scopeClaim))
                {
                    requestedScope = scopeClaim;
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
                });
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                return Results.Json(
                    new { error = "policy_unavailable", detail = ex.Message },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            switch (decision.Kind)
            {
                case AccessDecisionKind.Deny:
                    return Results.Json(
                        new { error = "denied", detail = decision.Reason },
                        statusCode: StatusCodes.Status403Forbidden);
                case AccessDecisionKind.NeedsPayment:
                {
                    // §Payment Required: Location MUST be present.
                    if (string.IsNullOrWhiteSpace(decision.PaymentUrl))
                    {
                        return Results.Json(
                            new { error = "policy_error", detail = "NeedsPayment requires a payment Location" },
                            statusCode: StatusCodes.Status500InternalServerError);
                    }
                    ctx.Response.Headers.Location = decision.PaymentUrl;
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    return Results.Json(
                        new { error = "payment_required" },
                        statusCode: StatusCodes.Status402PaymentRequired);
                }
                case AccessDecisionKind.NeedsInteraction:
                {
                    var entry = pending.Add(audience, requestedScope, agentId, agentConfirmationKey, policyClaims);
                    entry.OriginPersonServerHost = originPsHost;
                    ctx.Response.Headers.Location = $"{options.PendingPathPrefix}/{entry.Id}";
                    ctx.Response.Headers["Retry-After"] = "1";
                    ctx.Response.Headers["Cache-Control"] = "no-store";
                    ctx.Response.Headers[AAuthRequirementHeader.Name] =
                        Interaction.Format($"{issuer}{loginPath}", entry.Id);
                    return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                }
                case AccessDecisionKind.NeedsClaims:
                {
                    var entry = pending.Add(
                        audience, requestedScope, agentId, agentConfirmationKey, policyClaims, decision.RequiredClaims);
                    entry.OriginPersonServerHost = originPsHost;
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
                    return Results.Ok(new
                    {
                        auth_token = Mint(
                            audience, agentId, requestedScope, agentConfirmationKey,
                            decision.Subject, allowTenant, allowClaims),
                        expires_in = 3600,
                    });
            }
        });

        // -------------------------------------------------------------------
        // GET {PendingPathPrefix}/{id} — the PS polls the deferred verdict.
        // -------------------------------------------------------------------
        app.MapGet($"{options.PendingPathPrefix}/{{id}}", (HttpContext ctx, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null)
            {
                return Results.NotFound(new { error = "unknown_interaction" });
            }

            if (AuthorizePsCaller(ctx, entry) is { } pollFailure)
            {
                return pollFailure;
            }

            switch (entry.Status)
            {
                case AccessPendingStatus.Allowed:
                {
                    var (tenant, claims) = ProjectIdentityClaims(entry.SuppliedClaims, entry.RequiredClaims);
                    return Results.Ok(new
                    {
                        auth_token = Mint(
                            entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey,
                            entry.SuppliedSubject, tenant, claims),
                        expires_in = 3600,
                    });
                }
                case AccessPendingStatus.Denied:
                    return Results.Json(
                        new { error = "denied", detail = entry.DenyReason },
                        statusCode: StatusCodes.Status403Forbidden);
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
                        Interaction.Format($"{issuer}{loginPath}", entry.Id);
                    return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
            }
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
                return Results.NotFound(new { error = "unknown_interaction" });
            }

            if (AuthorizePsCaller(ctx, entry) is { } pushFailure)
            {
                return pushFailure;
            }

            JsonObject? pushed;
            try
            {
                pushed = await ctx.Request.ReadFromJsonAsync<JsonObject>();
            }
            catch (System.Text.Json.JsonException)
            {
                return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var directedSub = (string?)pushed?["sub"];
            if (string.IsNullOrEmpty(directedSub))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing directed sub" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

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
                });
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                return Results.Json(new { error = "policy_unavailable", detail = ex.Message },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            switch (decision.Kind)
            {
                case AccessDecisionKind.Allow:
                {
                    pending.MarkAllowed(entry.Id);
                    var (tenant, claims) = ProjectIdentityClaims(pushed, entry.RequiredClaims);
                    return Results.Ok(new
                    {
                        auth_token = Mint(
                            entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey,
                            directedSub, tenant, claims),
                        expires_in = 3600,
                    });
                }
                case AccessDecisionKind.Deny:
                    pending.MarkDenied(entry.Id, decision.Reason ?? "access denied");
                    return Results.Json(
                        new { error = "denied", detail = decision.Reason },
                        statusCode: StatusCodes.Status403Forbidden);
                case AccessDecisionKind.NeedsClaims:
                default:
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

        return app;
    }

    // Project the pushed identity claims into (tenant, additional claims). The
    // directed `sub` is emitted separately as the token's `sub`; `tenant` is a
    // first-class named claim (§Auth Token), the rest are additional claims.
    private static (string? Tenant, IReadOnlyDictionary<string, JsonNode?>? Claims) ProjectIdentityClaims(
        JsonObject? pushed, IReadOnlyList<string>? requiredClaims)
    {
        if (pushed is null || requiredClaims is null || requiredClaims.Count == 0)
        {
            return (null, null);
        }

        string? tenant = null;
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
            else
            {
                result[name] = node.DeepClone();
            }
        }

        return (tenant, result.Count > 0 ? result : null);
    }
}
