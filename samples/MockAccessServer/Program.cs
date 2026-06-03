using System.Text.Json.Nodes;
using AAuth;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
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
var asKey = AAuthKey.Generate();
const string AsKid = "as-1";
const string AsScope = "whoami";
var asIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5500";
ConsentHtml.Authority = Uri.TryCreate(asIssuer, UriKind.Absolute, out var asIssuerUri)
    ? asIssuerUri.Authority
    : asIssuer;
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Servers this AS will broker for. The PS authenticates to the AS
// via an HTTP Sig using the `jwks_uri` scheme; the helper resolves its key
// from that URI during signature verification and pins the URI's host to this
// trusted set (pre-established trust). An empty set trusts any signed caller.
var trustedPersonServers = builder.Configuration
    .GetSection("MockAccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];

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
switch (policyProvider)
{
    case "stub":
        var stubRequiredClaims = builder.Configuration
            .GetSection("AccessServer:RequireClaims").Get<string[]>() ?? [];
        var stubRequireConsent = builder.Configuration
            .GetValue("AccessServer:RequireConsent", false);
        builder.Services.AddSingleton<IAccessPolicy>(
            new StubAccessPolicy(stubRequiredClaims, stubRequireConsent));
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
// Keycloak login/consent round-trip (and across the §Claims Required push).
// Shared between the SDK helper and this sample's interaction endpoints.
builder.Services.AddSingleton<IAccessPendingStore, InMemoryAccessPendingStore>();

var app = builder.Build();

// -----------------------------------------------------------------------
// Map the whole AS pipeline in one call (§AS Token Endpoint): publishes
// /.well-known/aauth-access.json + JWKS, adds request-signature verification
// (excluding /.well-known and the browser-facing /interaction endpoints), and
// maps POST /token + GET|POST /pending/{id}. Policy decisions come from the
// configured IAccessPolicy; deferred decisions are parked in the shared
// IAccessPendingStore.
// -----------------------------------------------------------------------
app.MapAAuthAccessServer(new AAuthAccessServerOptions
{
    Issuer = asIssuer,
    SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = asKey },
    DefaultScope = AsScope,
    TrustedPersonServers = trustedPersonServers,
    InteractionLoginPath = "/interaction/login",
    // Demo convention: an agent whose id starts with `aauth:demo@` is treated
    // as holding the admin role. A production AS would receive the principal's
    // directory membership via the PS's §Claims Required push.
    DeriveAgentClaims = agentId => IsAdminAgent(agentId)
        ? new JsonObject { ["roles"] = new JsonArray(StubAccessPolicy.AdminRole) }
        : null,
});

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
app.MapGet("/interaction/login", (HttpContext ctx, string code) =>
{
    var pending = app.Services.GetRequiredService<IAccessPendingStore>();
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(),
            contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }

    // Interactive (Keycloak) policy: hand off to the OIDC provider.
    if (app.Services.GetRequiredService<IAccessPolicy>() is IInteractiveAccessPolicy interactive)
    {
        var redirectUri = $"{asIssuer.TrimEnd('/')}/interaction/callback";
        return Results.Redirect(interactive.BuildAuthorizationUrl(entry.Id, redirectUri));
    }

    // Stub policy: render the Access Server's own consent screen.
    return Results.Content(
        ConsentHtml.Prompt(code, entry.AgentId, entry.ResourceUrl, entry.Scope),
        contentType: "text/html");
});

// -----------------------------------------------------------------------
// POST /interaction/approve — the stub AS consent screen's Approve button.
// Flips the pending entry to Allowed so the agent's next poll mints the
// four-party auth token. Excluded from AAuth verification (browser form).
// -----------------------------------------------------------------------
app.MapPost("/interaction/approve", async (HttpContext ctx) =>
{
    var pending = app.Services.GetRequiredService<IAccessPendingStore>();
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(), contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }
    pending.MarkAllowed(entry.Id);
    return Results.Content(
        ConsentHtml.Approved(entry.AgentId, entry.ResourceUrl, entry.Scope),
        contentType: "text/html");
}).DisableAntiforgery();

// -----------------------------------------------------------------------
// POST /interaction/deny — the stub AS consent screen's Deny button. Marks
// the pending entry Denied so the agent's next poll receives 403 access_denied.
// -----------------------------------------------------------------------
app.MapPost("/interaction/deny", async (HttpContext ctx) =>
{
    var pending = app.Services.GetRequiredService<IAccessPendingStore>();
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            ConsentHtml.NotFound(), contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }
    pending.MarkDenied(entry.Id, "user denied at the Access Server");
    return Results.Content(
        ConsentHtml.Denied(entry.AgentId, entry.ResourceUrl, entry.Scope),
        contentType: "text/html");
}).DisableAntiforgery();

// -----------------------------------------------------------------------
// GET /interaction/callback?code={kcCode}&state={id} — Keycloak redirects
// the browser here after login/consent. We exchange the code for the user's
// token and ask Keycloak for the decision. On Allow/Deny we record the verdict
// on the pending entry; on NeedsClaims (Keycloak UMA need_info) we transition
// the entry into §Claims Required so the PS pushes the attributes on the same
// pending URL.
// -----------------------------------------------------------------------
app.MapGet("/interaction/callback", async (HttpContext ctx, string? code, string? state, string? error) =>
{
    var pending = app.Services.GetRequiredService<IAccessPendingStore>();
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

    switch (decision.Kind)
    {
        case AccessDecisionKind.Allow:
            pending.MarkAllowed(entry.Id);
            return Results.Content(InteractionHtml("Access granted", "You can return to your agent."), "text/html");
        case AccessDecisionKind.NeedsClaims:
            // Keycloak gathered a claim requirement (need_info). Transition the
            // entry into §Claims Required; the PS's ongoing poll sees
            // requirement=claims and pushes the attributes on the same URL.
            entry.RequiredClaims = decision.RequiredClaims;
            return Results.Content(InteractionHtml(
                "More information needed",
                "Your agent is providing the required details. You can return to it."), "text/html");
        case AccessDecisionKind.Deny:
        default:
            pending.MarkDenied(entry.Id, decision.Reason ?? "access denied");
            return Results.Content(InteractionHtml("Access denied", "You can close this window."), "text/html");
    }
});

app.Run();

// Minimal completion page shown to the user after the Keycloak round-trip.
static string InteractionHtml(string title, string body) =>
    ConsentHtml.Page(title, $"<p>{body}</p>");

// Demo convention shared with MockPersonServer: an agent whose id starts with
// `aauth:demo@` is treated as holding the admin role. A production AS would
// receive the principal's directory membership via the PS's claim push.
static bool IsAdminAgent(string agentId) =>
    agentId.StartsWith("aauth:demo@", StringComparison.Ordinal);

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

    public static string Prompt(string code, string agent, string resource, string scope) =>
        Page(
            "Approve agent at the Access Server",
            "<h1>An agent is requesting federated access on your behalf</h1>"
            + "<p>This is the <b>Access Server's</b> consent screen. In a real AS you would be "
            + "signed in via your identity provider (e.g. Keycloak) before reaching here.</p>"
            + $"<div class=row><b>Agent:</b> <code>{Enc(agent)}</code></div>"
            + $"<div class=row><b>Resource:</b> <code>{Enc(resource)}</code></div>"
            + $"<div class=row><b>Scope:</b> <code>{Enc(scope)}</code></div>"
            + "<form method=post action=\"/interaction/approve\">"
            + $"<input type=hidden name=code value=\"{Enc(code)}\">"
            + "<button class=approve type=submit>Approve</button></form>"
            + "<form method=post action=\"/interaction/deny\">"
            + $"<input type=hidden name=code value=\"{Enc(code)}\">"
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
            + "The agent's next poll will receive <code>403 access_denied</code>.</p>"
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
namespace MockAccessServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
