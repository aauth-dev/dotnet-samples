using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using MockAccessServer;
using MockAccessServer.Policy;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Access Server (AS) configuration — the fourth party in federated access.
//
// In four-party (federated) access the resource issues a resource token
// whose `aud` is the AS (not the Person Server). The PS does not assert
// access itself; it federates to the AS by POSTing the resource token (and
// the agent token) to the AS `token_endpoint`. The AS evaluates policy and,
// when allowed, mints the `aa-auth+jwt` auth token — distinguished from a
// PS-issued one by `dwk = aauth-access.json`.
//
// For demo purposes the AS generates a fresh Ed25519 signing key on start.
// A production AS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5500).
//
// Phase 1 policy is a hard-coded "allow" stub. The pluggable `IAccessPolicy`
// seam (and the Keycloak-backed policy engine) arrive in later phases.
// -----------------------------------------------------------------------
var asKey = AAuthKey.Generate();
const string AsKid = "as-1";
const string AsScope = "whoami";
var asIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5500";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Servers this AS will broker for. The PS authenticates to the AS
// via an HTTP Sig using the `jwks_uri` scheme; we resolve its key from that
// URI during signature verification and additionally pin the URI's host to
// this trusted set (pre-established trust). An empty/missing set trusts any
// validly-signed caller (demo-friendly default).
var trustedPersonServers = builder.Configuration
    .GetSection("MockAccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];
var trustedPsHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var ps in trustedPersonServers)
{
    if (Uri.TryCreate(ps, UriKind.Absolute, out var psUri))
    {
        trustedPsHosts.Add(psUri.Authority);
    }
}

builder.Services.AddSingleton(asKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");

// -----------------------------------------------------------------------
// Policy Decision Point (S3). The AAuth crypto stays in this adapter; only
// the allow/deny/needs-interaction decision is delegated to an IAccessPolicy.
// The provider is config-selected (mirrors MockPersonServer:RequireConsent):
//   AccessServer:PolicyProvider = stub | keycloak   (default: stub)
// `stub` keeps `make e2e`/CI pure-.NET; `keycloak` delegates to Keycloak's
// Authorization Services. Selecting `keycloak` while Keycloak is unreachable
// fails closed (the policy denies / surfaces a 5xx) — never a silent fallback.
// -----------------------------------------------------------------------
var policyProvider = (builder.Configuration["AccessServer:PolicyProvider"] ?? "stub")
    .Trim().ToLowerInvariant();
switch (policyProvider)
{
    case "stub":
        builder.Services.AddSingleton<IAccessPolicy, StubAccessPolicy>();
        break;
    case "keycloak":
        var keycloakOptions = new KeycloakOptions();
        builder.Configuration.GetSection("AccessServer:Keycloak").Bind(keycloakOptions);
        builder.Services.AddSingleton(keycloakOptions);
        builder.Services.AddHttpClient("keycloak");
        builder.Services.AddSingleton<IAccessPolicy>(sp => new KeycloakAccessPolicy(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("keycloak"),
            sp.GetRequiredService<KeycloakOptions>()));
        break;
    default:
        throw new InvalidOperationException(
            $"Unknown AccessServer:PolicyProvider '{policyProvider}'. Expected 'stub' or 'keycloak'.");
}

// Parks in-flight federated decisions while the user completes an interactive
// Keycloak login/consent round-trip (only used by the keycloak provider).
builder.Services.AddSingleton<AccessPendingStore>();

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints — served BEFORE the verification middleware so the
// AS metadata document and JWKS are reachable without an AAuth signature.
// `MapAAuthAccessServerWellKnown` publishes /.well-known/aauth-access.json
// and the JWKS at /.well-known/jwks.json.
// -----------------------------------------------------------------------
app.MapAAuthAccessServerWellKnown(new AAuthAccessServerMetadataOptions
{
    Issuer = asIssuer,
    TokenEndpoint = $"{asIssuer.TrimEnd('/')}/token",
    SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = asKey },
});

// All other endpoints require an AAuth signature. The PS signs with the
// `jwks_uri` scheme (RequireIssuerVerification=false — that scheme carries
// no issuer/token of its own; the request signature only proves the PS
// possesses the key advertised at its jwks_uri). The browser-facing
// interactive endpoints carry no AAuth signature, so they are excluded too.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !ctx.Request.Path.StartsWithSegments("/interaction"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// -----------------------------------------------------------------------
// POST /token — the AS token endpoint (§"AS Token Endpoint").
//
// Flow:
//   1. AAuthVerificationMiddleware validates the RFC 9421 signature. The PS
//      authenticates via the `jwks_uri` scheme; the parsed key exposes the
//      PS's jwks_uri so we can pin trust to a known Person Server.
//   2. We read `agent_token` and `resource_token` from the JSON body.
//   3. We verify the agent token (typ=aa-agent+jwt, dwk=aauth-agent.json)
//      against the agent issuer's JWKS, extracting the agent id (`sub`) and
//      its confirmation key (`cnf.jwk`).
//   4. We verify the resource token (§"Resource Token Verification") with
//      `aud` = this AS, binding it to the agent + its key. The verified
//      resource `iss` becomes the auth token's `aud`.
//   5. We evaluate access policy (Phase 1: a hard-coded allow stub).
//   6. We mint an `aa-auth+jwt` with `dwk = aauth-access.json`, `iss` = this
//      AS, `aud` = the resource, bound to the agent's key, and return it.
// -----------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    // The PS authenticates with the jwks_uri scheme. Reject any other carrier.
    if (parsed.Scheme != AAuthConstants.Schemes.JwksUri)
    {
        return Results.Json(
            new { error = "invalid_carrier", detail = $"expected jwks_uri scheme, got {parsed.Scheme}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Pin the caller to a trusted Person Server (pre-established trust).
    if (trustedPsHosts.Count > 0)
    {
        var jwksUri = parsed.JwksUri;
        if (string.IsNullOrEmpty(jwksUri)
            || !Uri.TryCreate(jwksUri, UriKind.Absolute, out var psUri)
            || !trustedPsHosts.Contains(psUri.Authority))
        {
            return Results.Json(
                new { error = "untrusted_person_server", detail = $"jwks_uri '{jwksUri}' is not a trusted Person Server" },
                statusCode: StatusCodes.Status403Forbidden);
        }
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

    var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
    var metadataClient = app.Services.GetRequiredService<MetadataClient>();
    var jwksClient = app.Services.GetRequiredService<JwksClient>();

    // Step 3 — verify the agent token and extract the agent id + key.
    string agentId;
    AAuthKey agentConfirmationKey;
    try
    {
        var verifiedAgentToken = await tokenVerifier.VerifyWithJwksAsync(
            agentTokenJwt,
            metadataClient,
            jwksClient,
            AgentTokenBuilder.TokenType,
            AgentTokenBuilder.AgentDwk,
            expectedAudience: null);

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

    // Step 4 — verify the resource token. `aud` MUST be this AS (that is what
    // distinguishes four-party from three-party). The verified `iss` is the
    // resource and becomes the auth token's `aud`; the verified `scope` is
    // echoed into the issued auth token.
    string audience;
    var requestedScope = AsScope;
    try
    {
        var verifiedResourceToken = await tokenVerifier.VerifyResourceTokenAsync(
            resourceTokenJwt,
            expectedAudience: asIssuer,
            expectedAgentId: agentId,
            expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
            metadataClient,
            jwksClient);

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
        return Results.Json(
            new
            {
                error = expired ? "expired_resource_token" : "invalid_resource_token",
                detail = ex.Message,
            },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Step 5 — access policy. Delegated to the configured IAccessPolicy
    // (stub by default; Keycloak when opted in). The PS-asserted admin signal
    // is derived from the agent id convention for the demo (a production AS
    // would receive PS claims via the spec's claim-push mechanism); it is
    // surfaced to the policy as a `roles` claim for ABAC evaluation.
    var policy = app.Services.GetRequiredService<IAccessPolicy>();
    var policyClaims = IsAdminAgent(agentId)
        ? new JsonObject { ["roles"] = new JsonArray(StubAccessPolicy.AdminRole) }
        : null;
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
        // Fail closed: a policy backend that cannot be reached must not grant.
        return Results.Json(
            new { error = "policy_unavailable", detail = ex.Message },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    switch (decision.Kind)
    {
        case AccessDecisionKind.Deny:
            return Results.Json(
                new { error = "access_denied", detail = decision.Reason },
                statusCode: StatusCodes.Status403Forbidden);
        case AccessDecisionKind.NeedsInteraction:
        {
            // Park the mint inputs and tell the PS (which relays to the agent)
            // to send the user through the AS login endpoint while polling the
            // pending URL. The real verdict is produced on the callback.
            var pending = app.Services.GetRequiredService<AccessPendingStore>();
            var entry = pending.Add(audience, requestedScope, agentId, agentConfirmationKey, policyClaims);
            var loginUrl = $"{asIssuer.TrimEnd('/')}/interaction/login";
            ctx.Response.Headers.Location = $"/pending/{entry.Id}";
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] = AAuthInteraction.Format(loginUrl, entry.Id);
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
        }
        case AccessDecisionKind.Allow:
        default:
            break;
    }

    // Step 6 — mint the auth token (dwk = aauth-access.json).
    return Results.Ok(new { auth_token = MintAuthToken(audience, agentId, requestedScope, agentConfirmationKey), expires_in = 3600 });
});

// -----------------------------------------------------------------------
// GET /interaction/login?code={id} — browser entry point. Redirects the
// user to the Keycloak authorization endpoint (OIDC code flow). Excluded
// from AAuth verification (no signature; it is the user's browser).
// -----------------------------------------------------------------------
app.MapGet("/interaction/login", (HttpContext ctx, string code) =>
{
    var pending = app.Services.GetRequiredService<AccessPendingStore>();
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_interaction" });
    }

    if (app.Services.GetRequiredService<IAccessPolicy>() is not IInteractiveAccessPolicy interactive)
    {
        return Results.Json(
            new { error = "interaction_unsupported", detail = "configured policy is not interactive" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var redirectUri = $"{asIssuer.TrimEnd('/')}/interaction/callback";
    return Results.Redirect(interactive.BuildAuthorizationUrl(entry.Id, redirectUri));
});

// -----------------------------------------------------------------------
// GET /interaction/callback?code={kcCode}&state={id} — Keycloak redirects
// the browser here after login/consent. We exchange the code for the user's
// token, ask Keycloak for the decision, and record the verdict on the
// pending entry. The PS's poll of /pending/{id} then mints or denies.
// -----------------------------------------------------------------------
app.MapGet("/interaction/callback", async (HttpContext ctx, string? code, string? state, string? error) =>
{
    var pending = app.Services.GetRequiredService<AccessPendingStore>();
    var entry = state is null ? null : pending.Get(state);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_interaction" });
    }

    if (!string.IsNullOrEmpty(error))
    {
        pending.MarkDenied(entry.Id, $"login failed: {error}");
        return Results.Content(InteractionHtml("Access denied", "You can close this window."), "text/html");
    }

    if (string.IsNullOrEmpty(code))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing code" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    if (app.Services.GetRequiredService<IAccessPolicy>() is not IInteractiveAccessPolicy interactive)
    {
        return Results.Json(
            new { error = "interaction_unsupported", detail = "configured policy is not interactive" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var redirectUri = $"{asIssuer.TrimEnd('/')}/interaction/callback";
    var request = new AccessPolicyRequest
    {
        ResourceUrl = entry.ResourceUrl,
        Scope = entry.Scope,
        AgentId = entry.AgentId,
        Claims = entry.Claims,
        InteractionId = entry.Id,
    };

    AccessDecision decision;
    try
    {
        decision = await interactive.CompleteAsync(code, redirectUri, request);
    }
    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
    {
        pending.MarkDenied(entry.Id, "policy backend unavailable");
        return Results.Content(InteractionHtml("Login error", "Please try again later."), "text/html");
    }

    if (decision.Kind == AccessDecisionKind.Allow)
    {
        pending.MarkAllowed(entry.Id);
        return Results.Content(InteractionHtml("Access granted", "You can return to your agent."), "text/html");
    }

    pending.MarkDenied(entry.Id, decision.Reason ?? "access denied");
    return Results.Content(InteractionHtml("Access denied", "You can close this window."), "text/html");
});

// -----------------------------------------------------------------------
// GET /pending/{id} — the PS polls this (signed) for the deferred decision.
// Mirrors the PS pending shape so the SDK's DeferredPoller drives it:
//   202 + AAuth-Requirement while pending, 200 auth_token when allowed,
//   403 access_denied when denied.
// -----------------------------------------------------------------------
app.MapGet("/pending/{id}", (HttpContext ctx, string id) =>
{
    var pending = app.Services.GetRequiredService<AccessPendingStore>();
    var entry = pending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_interaction" });
    }

    switch (entry.Status)
    {
        case AccessPendingStatus.Allowed:
            return Results.Ok(new
            {
                auth_token = MintAuthToken(entry.ResourceUrl, entry.AgentId, entry.Scope, entry.AgentConfirmationKey),
                expires_in = 3600,
            });
        case AccessPendingStatus.Denied:
            return Results.Json(
                new { error = "access_denied", detail = entry.DenyReason },
                statusCode: StatusCodes.Status403Forbidden);
        case AccessPendingStatus.Pending:
        default:
            var loginUrl = $"{asIssuer.TrimEnd('/')}/interaction/login";
            ctx.Response.Headers.Location = $"/pending/{entry.Id}";
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] = AAuthInteraction.Format(loginUrl, entry.Id);
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }
});

// Minimal completion page shown to the user after the Keycloak round-trip.
static string InteractionHtml(string title, string body) =>
    $"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>"
    + $"<body style=\"font-family:sans-serif;margin:3rem\"><h1>{title}</h1><p>{body}</p></body></html>";

// Demo convention shared with MockPersonServer: an agent whose id starts with
// `aauth:demo@` is treated as holding the admin role. A production AS would
// receive the principal's directory membership via the PS's claim push.
static bool IsAdminAgent(string agentId) =>
    agentId.StartsWith("aauth:demo@", StringComparison.Ordinal);

// Mint the `aa-auth+jwt` (dwk = aauth-access.json) bound to the agent's key.
string MintAuthToken(string resourceUrl, string agentId, string scope, AAuthKey confirmationKey) =>
    new AuthTokenBuilder
    {
        Issuer = asIssuer,
        Audience = resourceUrl,
        Agent = agentId,
        AgentConfirmationKey = confirmationKey,
        Key = asKey,
        KeyId = AsKid,
        Subject = "pairwise-sub",
        Scope = scope,
        Dwk = AuthTokenBuilder.AccessDwk,
    }.Build();

app.Run();

// Marker type for `WebApplicationFactory<MockAccessServer.Entry>` in the
// integration tests, matching the MockPersonServer pattern.
namespace MockAccessServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
