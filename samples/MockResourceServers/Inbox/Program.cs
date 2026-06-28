using AAuth;
using AAuth.Crypto;
using AAuth.Server;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Inbox — Aria's resource-managed (two-party) email service.
//
// The Inbox demonstrates the AAuth-Access opaque-token flow
// (§AAuth-Access Response Header, §Resource-Managed Authorization). Aria reads
// the traveler's inbox to import trip confirmations, but the Inbox manages
// authorization ITSELF — via its OWN consent page — with no Person Server and no
// Access Server. It fills the role a first-party OAuth deployment plays when a
// service runs its own authorization server next to its API: the Inbox is both the
// authority that mints the token and the API that accepts it. The opaque token the
// Inbox hands back models an existing OAuth access token, bound to the agent's
// signature so it is useless as a standalone bearer token.
//
// Two spec-defined entry points, sharing one decision path:
//
//   REACTIVE   GET /messages
//     first call (no token) -> 202 + AAuth-Requirement: requirement=interaction
//                              (url = /consent, code) + Location = /pending/{code}
//     user approves at /consent, agent polls /pending/{code} -> 200 + AAuth-Access
//     later calls send Authorization: AAuth <token68> (signed) -> 200 + messages
//
//   PROACTIVE  POST /authorize  { "scope": "inbox.read" }   (§Authorization
//     Endpoint Request) -> same 202/interaction path, then AAuth-Access.
//
// The Inbox owns its own consent surface (/consent) — no PS/AS is involved.
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

// Self-issued resource key (fresh each startup; a production resource loads a
// stable key from secure storage), served via /.well-known/jwks.json.
var resourceKey = AAuthKey.Generate();
const string ResourceKid = "inbox-1";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5004";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// One DI call: verifier, discovery clients (pooled handler), JTI store, and the
// published metadata (access_mode + authorization_endpoint) — no manual
// HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.SigningKeys[ResourceKid] = resourceKey;
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SignatureWindow = signatureWindowSeconds;
    o.Name = "Aria Inbox";
    o.AccessMode = AAuthConstants.AccessModes.AAuthAccessToken;
    o.AuthorizationEndpoint = $"{resourceUrl}/authorize";
});

// Resource-managed interaction module: registers the opaque-token store, the
// interaction pending store, and the module options (consent page url + poll
// path). The SDK owns code generation, parking, the poll endpoint, and token
// issuance; the Inbox keeps only its own consent page.
builder.Services.AddAAuthResourceManaged(o =>
{
    o.ConsentUrl = $"{resourceUrl}/consent";
    o.PollPath = "/pending";
});

var app = builder.Build();

var store = app.Services.GetRequiredService<IOpaqueTokenStore>();

// Well-known metadata + JWKS from the DI-registered resource metadata. Served
// unsigned (no endpoint requirement metadata, so UseAAuth passes it through).
app.MapAAuthWellKnown();

// Resource-managed (two-party) access: the protected endpoints declare
// .RequireAAuthSignature(); this single post-routing middleware verifies the
// agent's HTTP signature only (no issuer check, no auth-token challenge). The
// consent pages and well-known stay unsigned.
app.UseRouting();
app.UseAAuth();

// Sample inbox contents (illustrative; not spec-defined).
string[] sampleMessages =
[
    "Flight confirmation - AC8472 SFO->YVR, 2026-07-14",
    "Hotel booking - Fairmont Pacific Rim, 3 nights",
    "Car rental - compact, YVR airport",
];

// GET / — unauthenticated flow index.
app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Inbox",
    accessMode = "aauth-access-token",
    flows = new[]
    {
        new { path = "/messages", entry = "reactive", note = "202 → consent → AAuth-Access → replay" },
        new { path = "/authorize", entry = "proactive", note = "POST { scope } → same consent path" },
    },
}));

// GET /messages — reactive entry point. Serve messages when authorized; else
// open a consent interaction.
app.MapGet("/messages", async (HttpContext ctx) =>
{
    var info = await ctx.ResolveAAuthAccessAsync(store, ctx.RequestAborted);
    if (info is not null)
    {
        return Results.Ok(new
        {
            scope = info.Scope,
            messages = sampleMessages,
        });
    }

    return ctx.RequireAAuthInteraction("inbox.read");
}).RequireAAuthSignature();

// POST /authorize — proactive entry point (§Authorization Endpoint Request).
// Same decision path as /messages.
app.MapAAuthAuthorizationEndpoint("/authorize", async (ctx, request) =>
{
    var info = await ctx.ResolveAAuthAccessAsync(store, ctx.RequestAborted);
    if (info is not null)
    {
        return Results.Ok(new { authorized = true, scope = info.Scope });
    }

    return ctx.RequireAAuthInteraction(request.Scope);
}).RequireAAuthSignature();

// The deferred-response poll target (§Resource-Managed Authorization): 202 while
// the user has not approved, 200 + AAuth-Access on approval. Mapped by the SDK
// from the module's PollPath; the Inbox owns no poll plumbing.
app.MapAAuthInteractionPoll().RequireAAuthSignature();

// GET /consent — the Inbox's OWN consent page (unsigned; the user visits it in a
// browser). Mirrors a classic OAuth "Connect your account" screen — and, like
// the Person Server's and Access Server's consent screens, notes that a real
// deployment would sign the user in first.
app.MapGet("/consent", (string? code, IInteractionPendingStore pending) =>
{
    var entry = string.IsNullOrEmpty(code) ? null : pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Aria Inbox</title>"
            + "<body style=\"font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem\">"
            + "<h1>Aria Inbox</h1><p>This access request is unknown or has expired.</p>",
            contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }

    var safeCode = System.Net.WebUtility.HtmlEncode(code);
    var html =
        "<!doctype html><meta charset=utf-8><title>Connect Aria to your Inbox</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#0d9488;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#99f6e4}"
        + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
        + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:6rem;color:#555}"
        + ".note{background:#f0fdfa;border:1px solid #99f6e4;border-radius:.4rem;padding:.6rem .8rem;margin:1rem 0}"
        + "form{margin-top:1.5rem}"
        + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
        + "button.approve{background:#6ee7b7;border-color:#34d399}</style>"
        + "<div class=badge><span class=dot></span>Aria Inbox</div>"
        + "<div class=sub>localhost:5004 — the resource runs its own login &amp; consent (no Person Server, no Access Server)</div>"
        + "<h1>An agent wants to connect to your inbox</h1>"
        + "<div class=note>This is the <b>Inbox's own</b> consent screen. In a real deployment the Inbox would "
        + "<b>sign you in first</b> — with a password, passkey, or an existing OAuth / SSO session — before showing "
        + "this, exactly like the &ldquo;Connect your account&rdquo; step when you link a third-party service. "
        + "(The mock skips the login and trusts whoever opens this link.)</div>"
        + $"<div class=row><b>Agent key:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.AgentJkt)}</code></div>"
        + "<div class=row><b>Wants to:</b> read your inbox (import trip confirmations)</div>"
        + $"<div class=row><b>Scope:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code></div>"
        + "<form method=post action=\"/consent/approve\">"
        + $"<input type=hidden name=code value=\"{safeCode}\">"
        + "<button id=approve class=approve type=submit>Approve</button>"
        + "</form>";
    return Results.Content(html, contentType: "text/html");
});

// POST /consent/approve — the user approves; mark the pending interaction done.
app.MapPost("/consent/approve", async (HttpContext ctx, IInteractionPendingStore pending) =>
{
    var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
    var code = form["code"].ToString();
    if (pending.Approve(code))
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Connected</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#0d9488;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600}h1{font-size:1.25rem}</style>"
            + "<div class=badge>Aria Inbox</div>"
            + "<h1>Access approved</h1>"
            + "<p id=done>You can return to your agent — it will now receive an access token and read your inbox.</p>",
            contentType: "text/html");
    }

    return Results.NotFound(new { error = "unknown_pending" });
});

app.Run();

// Marker type for `WebApplicationFactory<Inbox.Entry>` in integration tests.
namespace Inbox
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
