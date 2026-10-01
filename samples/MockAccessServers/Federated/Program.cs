using System.Text.Json.Nodes;
using AAuth;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using MockAccessServer.Policy;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Access Server (AS) configuration — the fourth party in federated access.
//
// In four-party (federated) access the resource issues a resource token
// whose `aud` is the AS (not the Person Server). The PS does not assert
// access itself; it federates to the AS by POSTing the resource token (and
// the agent token) to the AS `auth_token_endpoint`. The AS evaluates policy and,
// when allowed, mints the `aa-auth+jwt` auth token — distinguished from a
// PS-issued one by `dwk = aauth-access.json`.
//
// The full token-endpoint mechanics (signature + token verification, the
// §Claims Required composition, deferred polling, minting) live in the SDK
// helper `MapAAuthAccessServer`. This sample only supplies configuration and
// the pluggable `IAccessPolicy` (and, for Keycloak, the browser-facing
// interaction endpoints).
//
// For demo purposes the AS generates a fresh Ed25519 signing key on start.
// A production AS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5500).
// -----------------------------------------------------------------------
const string AsKid = "as-1";
const string AsScope = "wallet.read";
var asIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5500";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Servers this AS will broker for. The PS authenticates to the AS
// via an HTTP Sig using the `jwks_uri` scheme; the helper resolves its key
// from that URI during signature verification and pins the URI's host to this
// trusted set (pre-established trust). An empty configured set denies all PS
// callers; omit the setting only when intentionally accepting the SDK's open
// trust semantics.
var trustedPersonServers = builder.Configuration
    .GetSection("MockAccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];

builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
// Shared discovery clients (MetadataClient + JwksClient) with a pooled handler;
// no manual HttpClient wiring.
builder.Services.AddAAuthDiscovery(options => options.EgressPolicy = SampleEgress.Policy);

// -----------------------------------------------------------------------
// Access Server registration. MapAAuthAccessServer (below) publishes
// /.well-known/aauth-access.json + JWKS, adds request-signature verification
// (excluding /.well-known and the browser-facing /interaction endpoints), and
// maps POST /token + GET|POST /pending/{id}. Deferred decisions are parked in
// the SDK's default in-memory pending store, shared with this sample's
// interaction endpoints while the user completes an interactive Keycloak
// login/consent round-trip (and across the §Claims Required push).
// -----------------------------------------------------------------------
var accessServer = builder.Services.AddAAuthAccessServer(configure: options =>
    {
        options.EgressPolicy = SampleEgress.Policy;
        options.Issuer = asIssuer;
        options.SigningKeys = new AAuthSigningKeySet(AsKid, AAuthKey.Generate());
        options.DefaultScope = AsScope;
        options.InteractionLoginPath = "/interaction/login";
    })
    .WithTrust(trust => trust.PersonServers.Allowed = new HashSet<string>(trustedPersonServers));

// -----------------------------------------------------------------------
// Policy Decision Point (S3). The AAuth crypto stays in the SDK helper; only
// the allow/deny/needs-interaction/needs-claims decision is delegated to an
// IAccessPolicy. The provider is config-selected (mirrors
// MockPersonServer:RequireConsent):
//   AccessServer:PolicyProvider = stub | keycloak   (default: stub)
// `stub` keeps `make e2e`/CI pure-.NET; `keycloak` delegates to Keycloak's
// Authorization Services. Selecting `keycloak` while Keycloak is unreachable
// fails closed (the policy denies / surfaces a 5xx) — never a silent fallback.
// -----------------------------------------------------------------------
var policyProvider = (builder.Configuration["AccessServer:PolicyProvider"] ?? "stub")
    .Trim().ToLowerInvariant();
var walletRules = new WalletPolicyRules(builder.Configuration["AAuth:Wallet"] ?? "http://localhost:5003",
    builder.Configuration["AAuth:Concierge"] ?? "http://localhost:5200");
switch (policyProvider)
{
    case "stub":
        var stubRequiredClaims = builder.Configuration
            .GetSection("AccessServer:RequireClaims").Get<string[]>() ?? [];
        var stubRequireConsent = builder.Configuration
            .GetValue("AccessServer:RequireConsent", false);
        accessServer.UsePolicy(new StubAccessPolicy(stubRequiredClaims, stubRequireConsent, walletRules));
        break;
    case "keycloak":
        var keycloakOptions = new KeycloakOptions();
        builder.Configuration.GetSection("AccessServer:Keycloak").Bind(keycloakOptions);
        builder.Services.AddSingleton(keycloakOptions);
        builder.Services.AddHttpClient("keycloak");
        accessServer.UsePolicy(sp => new KeycloakAccessPolicy(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("keycloak"),
            sp.GetRequiredService<KeycloakOptions>(), walletRules));
        break;
    default:
        throw new InvalidOperationException(
            $"Unknown AccessServer:PolicyProvider '{policyProvider}'. Expected 'stub' or 'keycloak'.");
}

var app = builder.Build();
var asIdentity = app.Services.GetRequiredKeyedService<IAAuthServerIdentity>(AAuthAccessServerBuilder.DefaultName);
ConsentHtml.Authority = new Uri(asIdentity.Issuer).Authority;
var browserConsent = new BrowserConsentSessions("AAuth.Federated.Consent",
    policyProvider == "stub" && builder.Configuration.GetValue<bool>("AAuth:EnableIsolatedDemoConsent") ? "isolated-federated-demo" : null);

// Map the whole AS pipeline in one call (§AS Token Endpoint); policy decisions
// come from the configured IAccessPolicy.
app.MapAAuthAccessServer();

// -----------------------------------------------------------------------
// GET /interaction/login?code={id} — browser entry point.
//
// * Keycloak policy  → 302-redirect to the Keycloak OIDC code flow.
// * stub policy      → render the AS's own consent screen (Approve / Deny),
//                      so that from the agent's perspective the stub and
//                      Keycloak are identical (same 202 → interaction URL →
//                      poll → mint); only the interaction URL's destination
//                      differs.
//
// Excluded from AAuth verification (no signature; it is the user's browser).
// -----------------------------------------------------------------------
app.MapMethods("/interaction/login", ["GET", "POST"], async (HttpContext ctx,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPendingStore pending,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPolicy policy) =>
{
    var entered = await browserConsent.EnterAsync(ctx, code => pending.GetByCode(code) is { } candidate
        ? new BrowserPendingRequest(candidate.Id, candidate.PendingExpiresAt, candidate.Browser, candidate.Lifecycle) : null,
        externalLogin: policyProvider == "keycloak");
    if (entered.Error is not null) return entered.Error;
    var entry = pending.Get(entered.Id!);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(),
            contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }

    // Interactive (Keycloak) policy: hand off to the OIDC provider.
    if (policy is IInteractiveAccessPolicy interactive)
    {
        var redirectUri = asIdentity.Url("/interaction/callback");
        return Results.Redirect(interactive.BuildAuthorizationUrl(entered.Decision!, redirectUri));
    }

    // Stub policy: render the Access Server's own consent screen.
    return Results.Content(
        ConsentHtml.Prompt(browserConsent.Fields(ctx, entered.Decision!), entry.AgentId, entry.ResourceUrl, entry.Scope),
        contentType: "text/html");
});

// -----------------------------------------------------------------------
// POST /interaction/approve — the stub AS consent screen's Approve button.
// Flips the pending entry to Allowed so the agent's next poll mints the
// four-party auth token. Excluded from AAuth verification (browser form).
// -----------------------------------------------------------------------
app.MapPost("/interaction/approve", async (HttpContext ctx,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPendingStore pending) =>
{
    if (policyProvider != "stub") return AAuthProblemDetails.Create("denied", statusCode: 403);
    var decision = await browserConsent.DecideAsync(ctx);
    if (decision.Error is not null) return decision.Error;
    var code = decision.Decision!.Id;
    if (string.IsNullOrEmpty(code))
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing 'code'", statusCode: StatusCodes.Status400BadRequest);
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(), contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }
    return await decision.Decision.ApplyAsync(ctx, () =>
    {
        if (entry.Status != AccessPendingStatus.Pending || entry.PendingExpiresAt <= DateTimeOffset.UtcNow)
            return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
        entry.Status = AccessPendingStatus.Allowed;
        return Results.Content(
            ConsentHtml.Approved(entry.AgentId, entry.ResourceUrl, entry.Scope),
            contentType: "text/html");
    });
});

// -----------------------------------------------------------------------
// POST /interaction/deny — the stub AS consent screen's Deny button. Marks
// the pending entry Denied so the agent's next poll receives 403 denied.
// -----------------------------------------------------------------------
app.MapPost("/interaction/deny", async (HttpContext ctx,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPendingStore pending) =>
{
    if (policyProvider != "stub") return AAuthProblemDetails.Create("denied", statusCode: 403);
    var decision = await browserConsent.DecideAsync(ctx);
    if (decision.Error is not null) return decision.Error;
    var code = decision.Decision!.Id;
    if (string.IsNullOrEmpty(code))
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing 'code'", statusCode: StatusCodes.Status400BadRequest);
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(), contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }
    return await decision.Decision.ApplyAsync(ctx, () =>
    {
        if (entry.Status is AccessPendingStatus.Allowed or AccessPendingStatus.Denied
            || entry.PendingExpiresAt <= DateTimeOffset.UtcNow)
            return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
        entry.Status = AccessPendingStatus.Denied;
        entry.DenyReason = "user denied at the Access Server";
        return Results.Content(
            ConsentHtml.Denied(entry.AgentId, entry.ResourceUrl, entry.Scope),
            contentType: "text/html");
    });
});

// -----------------------------------------------------------------------
// GET /interaction/callback?code={kcCode}&state={id} — Keycloak redirects
// the browser here after login/consent. We exchange the code for the user's
// token and ask Keycloak for the decision. On Allow/Deny we record the verdict
// on the pending entry; on NeedsClaims (Keycloak UMA need_info) we transition
// the entry into §Claims Required so the PS pushes the attributes on the same
// pending URL.
// -----------------------------------------------------------------------
app.MapGet("/interaction/callback", async (HttpContext ctx, string? code, string? state, string? error,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPendingStore pending,
    [FromKeyedServices(AAuthAccessServerBuilder.DefaultName)] IAccessPolicy policy) =>
{
    if (policyProvider != "keycloak") return AAuthProblemDetails.Create("denied", statusCode: 403);
    var session = await browserConsent.DecideAsync(ctx, externalLogin: true, externalState: state);
    if (session.Error is not null) return session.Error;
    var entry = pending.Get(session.Decision!.Id);
    if (entry is null)
    {
        return AAuth.Server.AAuthProblemDetails.Polling(AAuth.Errors.PollingErrorCode.InvalidCode);
    }

    return await session.Decision.ApplyAsync(ctx, async () =>
    {
        if (entry.Status != AccessPendingStatus.Pending || entry.PendingExpiresAt <= DateTimeOffset.UtcNow)
            return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
        if (!string.IsNullOrEmpty(error))
        {
            entry.Status = AccessPendingStatus.Denied;
            entry.DenyReason = $"login failed: {error}";
            return Results.Content(InteractionHtml("Access denied", "You can close this window."), "text/html");
        }

        if (string.IsNullOrEmpty(code))
        {
            return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing code", statusCode: StatusCodes.Status400BadRequest);
        }

        if (policy is not IInteractiveAccessPolicy interactive)
        {
            return AAuth.Server.AAuthProblemDetails.Create("interaction_unsupported", "configured policy is not interactive", statusCode: StatusCodes.Status400BadRequest);
        }

        var redirectUri = asIdentity.Url("/interaction/callback");
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
            entry.Status = AccessPendingStatus.Denied;
            entry.DenyReason = "policy backend unavailable";
            return Results.Content(InteractionHtml("Login error", "Please try again later."), "text/html");
        }

        ctx.RequestAborted.ThrowIfCancellationRequested();
        switch (decision.Kind)
        {
            case AccessDecisionKind.Allow:
                entry.Status = AccessPendingStatus.Allowed;
                return Results.Content(InteractionHtml("Access granted", "You can return to your agent."), "text/html");
            case AccessDecisionKind.NeedsClaims:
                // Keycloak gathered a claim requirement (need_info). Transition the
                // entry into §Claims Required; the PS's ongoing poll sees
                // requirement=claims and pushes the attributes on the same URL.
                if (AAuth.Headers.ClaimsRequirement.ContainsForbiddenClaimName(decision.RequiredClaims))
                {
                    entry.Status = AccessPendingStatus.Denied;
                    entry.DenyReason = "policy requested protocol-owned claims";
                    return Results.Content(InteractionHtml("Access denied", "The policy requested unsupported identity claims."), "text/html");
                }
                entry.RequiredClaims = decision.RequiredClaims;
                return Results.Content(InteractionHtml(
                    "More information needed",
                    "Your agent is providing the required details. You can return to it."), "text/html");
            case AccessDecisionKind.Deny:
            default:
                entry.Status = AccessPendingStatus.Denied;
                entry.DenyReason = decision.Reason ?? "access denied";
                return Results.Content(InteractionHtml("Access denied", "You can close this window."), "text/html");
        }
    });
});

app.Run();

// Minimal completion page shown to the user after the Keycloak round-trip.
static string InteractionHtml(string title, string body) =>
    ConsentHtml.Page(title, $"<h1>{System.Net.WebUtility.HtmlEncode(title)}</h1><p>{System.Net.WebUtility.HtmlEncode(body)}</p>");

// -----------------------------------------------------------------------
// Access Server consent-screen HTML. Mirrors the MockPersonServer consent
// screen's shape, but with an unmistakable **Access Server** identity banner
// (red, matching the four-party swimlane) so the user always knows which
// server they are approving at — the resource-owning Person Server, or the
// federated Access Server.
// -----------------------------------------------------------------------
static class ConsentHtml
{
    private const string Style =
        "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#b91c1c;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#fecaca}"
        + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
        + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:6rem;color:#555}"
        + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
        + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
        + "button.approve{background:#6ee7b7;border-color:#34d399}"
        + "button.deny{background:#fecaca;border-color:#f87171}</style>";

    // Identity banner: makes it unmistakable the user is at the Access Server.
    // <see cref="Authority"/> is set once at startup from the configured issuer.
    private static string Banner =>
        "<div class=badge><span class=dot></span>Access Server</div>"
        + $"<div class=sub>{Enc(Authority)} — the federated authority that issues the four-party auth token</div>";

    /// <summary>The issuer host authority shown in the banner (e.g. <c>localhost:5500</c>).</summary>
    public static string Authority { get; set; } = "localhost:5500";

    public static string Page(string title, string bodyHtml) =>
        "<!doctype html><meta charset=utf-8><title>" + Enc(title) + " — Access Server</title>"
        + Style + Banner + bodyHtml;

    public static string Prompt(string fields, string agent, string resource, string scope) =>
        Page(
            "Approve agent at the Access Server",
            "<h1>An agent is requesting federated access on your behalf</h1>"
            + "<p>Signed in as the isolated demo user at the <b>Access Server</b>.</p>"
            + $"<div class=row><b>Agent:</b> <code>{Enc(agent)}</code></div>"
            + $"<div class=row><b>Resource:</b> <code>{Enc(resource)}</code></div>"
            + $"<div class=row><b>Scope:</b> <code>{Enc(scope)}</code></div>"
            + "<form method=post action=\"/interaction/approve\">"
            + fields
            + "<button class=approve type=submit>Approve</button></form>"
            + "<form method=post action=\"/interaction/deny\">"
            + fields
            + "<button class=deny type=submit>Deny</button></form>");

    public static string Approved(string agent, string resource, string scope) =>
        Page(
            "Approved",
            "<h1>Approved</h1>"
            + $"<p>You granted <code>{Enc(agent)}</code> federated access to "
            + $"<code>{Enc(resource)}</code> with scope <code>{Enc(scope)}</code> "
            + "at the <b>Access Server</b>.</p>"
            + "<p>You can close this tab — the agent will receive its auth token on its next poll.</p>");

    public static string Denied(string agent, string resource, string scope) =>
        Page(
            "Denied",
            "<h1>Denied</h1>"
            + $"<p>You denied <code>{Enc(agent)}</code>'s federated request for "
            + $"<code>{Enc(resource)}</code> at the <b>Access Server</b>. "
            + "The agent's next poll will receive <code>403 denied</code>.</p>"
            + "<p>You can close this tab.</p>");

    public static string NotFound() =>
        Page(
            "Unknown or expired code",
            "<h1>Unknown or expired code</h1>"
            + "<p>This consent request is no longer pending at the Access Server. The agent may "
            + "have already received an auth token, or the code was never issued.</p>");

    private static string Enc(string value) => System.Net.WebUtility.HtmlEncode(value);
}

// Marker type for `WebApplicationFactory<MockAccessServer.Entry>` in the
// integration tests, matching the MockPersonServer pattern.
namespace Federated
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
