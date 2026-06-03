using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.DependencyInjection;
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
        builder.Services.AddSingleton<IAccessPolicy>(new StubAccessPolicy(stubRequiredClaims));
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
// GET /interaction/login?code={id} — browser entry point. Redirects the
// user to the configured identity provider (Keycloak OIDC code flow).
// Excluded from AAuth verification (no signature; it is the user's browser).
// -----------------------------------------------------------------------
app.MapGet("/interaction/login", (HttpContext ctx, string code) =>
{
    var pending = app.Services.GetRequiredService<IAccessPendingStore>();
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
    $"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>"
    + $"<body style=\"font-family:sans-serif;margin:3rem\"><h1>{title}</h1><p>{body}</p></body></html>";

// Demo convention shared with MockPersonServer: an agent whose id starts with
// `aauth:demo@` is treated as holding the admin role. A production AS would
// receive the principal's directory membership via the PS's claim push.
static bool IsAdminAgent(string agentId) =>
    agentId.StartsWith("aauth:demo@", StringComparison.Ordinal);

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
