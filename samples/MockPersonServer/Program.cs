using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using MockPersonServer;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Person Server configuration.
//
// For demo purposes the PS generates a fresh Ed25519 signing key on start.
// A production PS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5100). The issuer URL is also pinned to the value the
// agent puts in its agent token's `ps` claim, so it must match what
// callers configure.
//
// `MockPersonServer:RequireConsent` (default false) controls the user-
// consent gate. When false, every `/token` POST issues an auth token
// immediately — the autonomous-three-party path used by the AgentConsole
// sample and the §3.4 ThreePartyFlow integration test. When true, the PS
// returns 202 + an interaction requirement and the agent must poll the
// pending URL until `POST /admin/consent` records approval — this is what
// drives the GuidedTour's deferred / user-consent showcase and the §3.4
// ThreePartyUserConsentFlow integration test.
// -----------------------------------------------------------------------
var psKey = AAuthKey.Generate();
const string PsKid = "ps-1";
const string PsScope = "whoami";
var psIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5100";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var requireConsent = builder.Configuration.GetValue<bool>("MockPersonServer:RequireConsent");

builder.Services.AddSingleton(psKey);
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
builder.Services.AddSingleton<ConsentStore>();
builder.Services.AddSingleton<PendingStore>();
builder.Services.AddSingleton(sp =>
    new UpstreamTokenValidator(
        sp.GetRequiredService<MetadataClient>(),
        sp.GetRequiredService<JwksClient>()));

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints — served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------

// JWKS (reused from the shared resource helper — same shape).
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = psIssuer,
    ClientName = "Mock Person Server",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [PsScope] = "Issue AAuth auth tokens for WhoAmI",
    },
    SignatureWindow = signatureWindowSeconds,
});

// PS-specific metadata document.
app.MapAAuthPersonServerWellKnown(new AAuthPersonServerMetadataOptions
{
    Issuer = psIssuer,
    TokenEndpoint = $"{psIssuer.TrimEnd('/')}/token",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
});

// All other endpoints require an AAuth signature — except the
// /admin/* helpers, which are demo-only consent toggles and intentionally
// unsigned. A production PS would expose these only behind operator auth
// or wouldn't expose them at all.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !ctx.Request.Path.StartsWithSegments("/admin")
        && !ctx.Request.Path.StartsWithSegments("/interaction"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// -----------------------------------------------------------------------
// POST /token — the exchange endpoint.
//
// Flow:
//   1. AAuthVerificationMiddleware validates the RFC 9421 signature and
//      exposes the parsed carrier token (the agent's aa-agent+jwt) via
//      HttpContext.Items.
//   2. We read `resource_token` from the request body.
//   3. We mint an aa-auth+jwt whose:
//        - iss = this PS
//        - aud = the resource_token's iss (the resource)
//        - agent = agent identifier from the agent token
//        - cnf.jwk = the agent's confirmation key (binds PoP)
//   4. We return { "auth_token": "..." }.
//
// This mock does NOT verify the resource_token's signature — a production
// PS would fetch the resource's JWKS and verify it. Sufficient for the
// demo and for exercising the agent's three-party retry path.
// -----------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx, ConsentStore consent, PendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    // Only an agent token may exchange — refuse anything else.
    var tokenType = ctx.GetAAuthTokenType();
    if (tokenType != AAuthTokenType.AgentToken)
    {
        return Results.Json(
            new { error = "invalid_carrier_token", detail = $"expected {AAuthConstants.TokenTypes.AgentToken}, got {tokenType}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var agentId = (string?)parsed.Payload?["sub"];
    if (string.IsNullOrEmpty(agentId))
    {
        return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" },
            statusCode: StatusCodes.Status401Unauthorized);
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

    // Call-chaining: validate upstream_token if present using UpstreamTokenValidator
    // (§Upstream Token Verification steps 1-4).
    var upstreamTokenJwt = (string?)body?["upstream_token"];
    JsonObject? upstreamAct = null;
    if (!string.IsNullOrEmpty(upstreamTokenJwt))
    {
        var validator = app.Services.GetRequiredService<UpstreamTokenValidator>();
        // For this mock PS, trust all issuers. Production would maintain
        // a set of known ASes whose tokens the PS has previously brokered.
        var trustedIssuers = new HashSet<string> { psIssuer };

        // §Upstream Token Verification step 3: aud must match the intermediary
        // resource. Per §Call Chaining Identity, the intermediary self-issues
        // its agent token (iss = its resource URL). So agent_token.iss IS the
        // intermediary's resource identifier.
        var intermediaryResourceUrl = (string?)parsed.Payload?["iss"]
            ?? throw new InvalidOperationException("Agent token missing 'iss' claim.");

        var result = await validator.ValidateAsync(
            upstreamTokenJwt,
            expectedAudience: intermediaryResourceUrl,
            trustedIssuers);

        if (!result.IsValid)
        {
            return Results.Json(new { error = "invalid_upstream_token", detail = result.Error },
                statusCode: StatusCodes.Status400BadRequest);
        }

        // The result contains the fully nested act (intermediary wrapping upstream).
        upstreamAct = result.UpstreamAct;
    }

    // Decode the resource token's `iss` claim — that's the resource URL
    // and becomes the auth token's `aud`.
    string audience;
    try
    {
        var segments = resourceTokenJwt.Split('.');
        if (segments.Length != 3)
        {
            throw new FormatException("not a compact JWT");
        }
        var payload = (JsonObject?)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))
            ?? throw new FormatException("payload is not a JSON object");
        audience = (string?)payload["iss"]
            ?? throw new FormatException("resource_token missing iss");
        // The resource_token signature is NOT verified by this mock PS (see
        // file-level comment). Validate at least that `iss` is an absolute
        // http(s) URL so a forged token can't smuggle a `javascript:` or
        // garbage `aud` into the minted auth_token.
        if (!Uri.TryCreate(audience, UriKind.Absolute, out var audUri)
            || (audUri.Scheme != Uri.UriSchemeHttps && audUri.Scheme != Uri.UriSchemeHttp))
        {
            throw new FormatException("resource_token iss must be an absolute http(s) URL");
        }
    }
    catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request", detail = $"malformed resource_token: {ex.Message}" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    // Consent gate. If the PS is configured to require consent and the
    // (agent, resource, scope) triple hasn't been approved yet, park the
    // request and tell the agent to direct its user to the interaction
    // endpoint while polling the pending URL.
    if (requireConsent && !consent.IsConsented(agentId, audience, PsScope))
    {
        var entry = pending.Add(agentId, audience, PsScope, resourceTokenJwt, parsed.ConfirmationKey!, upstreamAct);
        var location = $"/pending/{entry.Id}";
        var interactionUrl = $"{psIssuer.TrimEnd('/')}/interaction";
        ctx.Response.Headers.Location = location;
        ctx.Response.Headers["Retry-After"] = "0";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthInteraction.Format(interactionUrl, entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    var authToken = IssueAuthToken(agentId, audience, parsed.ConfirmationKey!, upstreamAct);
    return Results.Ok(new { auth_token = authToken });
});

// -----------------------------------------------------------------------
// GET /pending/{id} — the agent polls here while the user (allegedly)
// goes off and approves the request at the interaction endpoint. Signed,
// just like /token. Returns:
//   * 202 + same AAuth-Requirement header while pending (no consent yet)
//   * 200 + { auth_token } once consent has been recorded
//   * 404 if the pending id doesn't exist (e.g. already resolved + GC'd)
// -----------------------------------------------------------------------
app.MapGet("/pending/{id}", (HttpContext ctx, string id, ConsentStore consent, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    // Explicit denial — return 403 access_denied so the agent can
    // distinguish "user said no" from "timed out / unknown id".
    if (entry.Denied)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "access_denied", detail = "the user denied this request" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    if (!consent.IsConsented(entry.Agent, entry.Resource, entry.Scope))
    {
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthInteraction.Format($"{psIssuer.TrimEnd('/')}/interaction", id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // Consent was recorded — mint the auth token bound to the same agent
    // confirmation key captured when the pending entry was created. We
    // intentionally leave the entry in place so a slow poller still gets
    // a deterministic answer on its next request; a production PS would
    // expire pending entries on a timer.
    var authToken = IssueAuthToken(entry.Agent, entry.Resource, entry.AgentConfirmationKey, entry.UpstreamAct);
    return Results.Ok(new { auth_token = authToken });
});

// -----------------------------------------------------------------------
// DEMO-ONLY admin endpoints. A real PS would NEVER expose unauthenticated
// consent flips. These exist so the GuidedTour's "User approves" button
// and the §3.4 user-consent integration test can drive the consent
// transition deterministically. Body shape:
//   { "agent": "aauth:...@...", "resource": "https://whoami/", "scope": "whoami" }
// `scope` is optional and defaults to the PS's single demo scope.
// -----------------------------------------------------------------------
app.MapPost("/admin/consent", async (HttpContext ctx, ConsentStore consent) =>
{
    var (agent, resource, scope, err) = await ReadAdminBodyAsync(ctx);
    if (err is not null) { return err; }
    consent.Grant(agent!, resource!, scope!);
    return Results.Ok(new { ok = true, agent, resource, scope });
});

app.MapPost("/admin/revoke", async (HttpContext ctx, ConsentStore consent) =>
{
    var (agent, resource, scope, err) = await ReadAdminBodyAsync(ctx);
    if (err is not null) { return err; }
    consent.Revoke(agent!, resource!, scope!);
    return Results.Ok(new { ok = true, agent, resource, scope });
});

// Demo-only: wipe all consent + pending state back to baseline so an automated
// test harness can start each spec from a known-empty store (see the E2E suite's
// resetConsent helper). A production PS would never expose this.
app.MapPost("/admin/reset", (ConsentStore consent, PendingStore pending) =>
{
    consent.Clear();
    pending.Clear();
    return Results.Ok(new { ok = true });
});

// User-facing interaction page. The 202 from `POST /token` told the
// agent's user to visit this URL with `?code={pending-id}`. In a real PS
// this page would be behind the user's signed-in browser session
// (cookie/passkey/SSO); here we trust the demo environment and just look
// up the pending entry by its single-use code. The form submits to
// /interaction/approve or /interaction/deny.
app.MapGet("/interaction", (string? code, PendingStore pending) =>
{
    if (string.IsNullOrEmpty(code))
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Mock PS consent</title>"
            + "<h1>Missing code</h1>"
            + "<p>This page must be visited with a <code>?code=…</code> query parameter from a pending AAuth interaction.</p>",
            contentType: "text/html",
            statusCode: StatusCodes.Status400BadRequest);
    }

    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Mock PS consent</title>"
            + "<h1>Unknown or expired code</h1>"
            + "<p>This consent request is no longer pending. The agent may have already received an auth token, or the code was never issued.</p>",
            contentType: "text/html",
            statusCode: StatusCodes.Status404NotFound);
    }

    var html =
        "<!doctype html><meta charset=utf-8><title>Approve agent at Mock PS</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}"
        + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:6rem;color:#555}"
        + "form{margin-top:1.5rem;display:flex;gap:.75rem}"
        + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
        + "button.approve{background:#6ee7b7;border-color:#34d399}"
        + "button.deny{background:#fecaca;border-color:#f87171}</style>"
        + "<h1>An agent is requesting access on your behalf</h1>"
        + "<p>This is the Mock Person Server's consent screen. In a real PS you would be signed in via cookie / passkey / SSO before reaching here.</p>"
        + $"<div class=row><b>Agent:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code></div>"
        + $"<div class=row><b>Resource:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Resource)}</code></div>"
        + $"<div class=row><b>Scope:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code></div>"
        + "<form method=post action=\"/interaction/approve\">"
        + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
        + "<button class=approve type=submit>Approve</button>"
        + "</form>"
        + "<form method=post action=\"/interaction/deny\">"
        + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
        + "<button class=deny type=submit>Deny</button>"
        + "</form>";
    return Results.Content(html, contentType: "text/html");
});

// Approve handler. Reads the pending id from the posted form, records
// consent for the entry's (agent, resource, scope) triple, and shows a
// confirmation page. Idempotent: re-submitting a code whose entry is
// already approved still 200s.
app.MapPost("/interaction/approve", async (HttpContext ctx, ConsentStore consent, PendingStore pending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    consent.Grant(entry.Agent, entry.Resource, entry.Scope);
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Approved</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}</style>"
        + "<h1>Approved</h1>"
        + $"<p>You granted <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code> access to "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.Resource)}</code> with scope "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code>.</p>"
        + "<p>You can close this tab — the agent will receive its auth token on its next poll.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

// Deny handler. Marks the pending entry as denied (rather than removing
// it) so the agent's next poll receives a deterministic
// `403 access_denied` instead of an ambiguous `404 unknown_pending`.
app.MapPost("/interaction/deny", async (HttpContext ctx, PendingStore pending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    pending.Deny(code);
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Denied</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}</style>"
        + "<h1>Denied</h1>"
        + $"<p>You denied <code>{System.Net.WebUtility.HtmlEncode(entry.Agent)}</code>'s request. The agent's next poll will receive <code>403 access_denied</code>.</p>"
        + "<p>You can close this tab.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

app.Run();

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
string IssueAuthToken(string agentId, string audience, IAAuthKey confirmationKey, JsonObject? upstreamAct = null)
    => new AuthTokenBuilder
    {
        Issuer = psIssuer,
        Audience = audience,
        Agent = agentId,
        AgentConfirmationKey = confirmationKey,
        Key = psKey,
        KeyId = PsKid,
        Subject = "pairwise-sub",
        Scope = PsScope,
        UpstreamAct = upstreamAct,
    }.Build();

async Task<(string? Agent, string? Resource, string? Scope, IResult? Error)> ReadAdminBodyAsync(HttpContext ctx)
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return (null, null, null, Results.Json(
            new { error = "invalid_request", detail = "body is not valid JSON" },
            statusCode: StatusCodes.Status400BadRequest));
    }

    var agent = (string?)body?["agent"];
    var resource = (string?)body?["resource"];
    var scope = (string?)body?["scope"] ?? PsScope;
    if (string.IsNullOrEmpty(agent) || string.IsNullOrEmpty(resource))
    {
        return (null, null, null, Results.Json(
            new { error = "invalid_request", detail = "missing 'agent' or 'resource'" },
            statusCode: StatusCodes.Status400BadRequest));
    }
    return (agent, resource, scope, null);
}

// Marker type for `WebApplicationFactory<MockPersonServer.Entry>` in the
// integration tests. We don't expose `public partial class Program;` here
// because the WhoAmI sample already declares its own global `Program`, and
// adding both project references to a test assembly would make `Program`
// ambiguous. A dedicated, namespaced marker sidesteps that.
namespace MockPersonServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
