using System.Text.Json.Nodes;
using AAuth;
using AAuth.Access;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Governance;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
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
const string PsScope = "calendar.read";
const string PsAdminScope = "calendar.write";
// Demo identity claims the mock PS asserts about the user. A production PS
// would resolve these from the signed-in user's directory entry. These let
// the Calendar `/events/admin` (RBAC) endpoint succeed end-to-end.
//
// Roles/groups are asserted ONLY for recognized "admin" demo agents (those
// whose id is `aauth:demo@...`). Any other agent receives an auth token
// without the role, so role-based DENIAL is exercised end-to-end (a guest
// agent calling `/events/admin` gets a 403). A production PS would resolve the
// principal's directory membership instead of a hard-coded prefix.
string[] demoRoles = ["calendar.owner"];
string[] demoGroups = ["demo-users"];
// Identity claims the PS can release for the bound principal when an Access
// Server asks for them via the §Claims Required push. A production PS would
// resolve these from its identity store keyed by the authenticated principal.
var demoUserClaims = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["email"] = "demo@person.example",
    ["tenant"] = "demo-tenant",
    ["name"] = "Demo User",
};
var psIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5100";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var requireConsent = builder.Configuration.GetValue<bool>("MockPersonServer:RequireConsent");
// Four-party (federated) trust: the Access Servers this PS is willing to
// federate to. When a resource token's `aud` is one of these (rather than the
// PS itself), the PS forwards a signed PS->AS token request instead of issuing
// the auth token directly. Pre-established trust — a production PS would manage
// this set per the operator's federation agreements.
var trustedAccessServers = builder.Configuration
        .GetSection("MockPersonServer:TrustedAccessServers").Get<string[]>()
    ?? ["http://localhost:5500"];

builder.Services.AddSingleton(psKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton(new TokenVerifier());
// Shared discovery clients (MetadataClient + JwksClient) with a pooled handler;
// no manual HttpClient wiring.
builder.Services.AddAAuthDiscovery();
builder.Services.AddSingleton<ConsentStore>();

// Person Server decision seams. The SDK's MapAAuthPersonServer owns the protocol
// (verification, mint, federation, the mission three-gate + the clarification
// round-trip); these supply only the demo's decisions:
//   * identity + the non-mission consent gate (over ConsentStore);
//   * the id-keyed pending store, bridged to the (agent,resource,scope) ConsentStore.
builder.Services.AddSingleton<IIdentityClaimsAsserter>(sp =>
    new SampleIdentityClaimsAsserter(
        sp.GetRequiredService<ConsentStore>(), requireConsent, demoRoles, demoGroups, demoUserClaims));
builder.Services.AddSingleton<IPersonPendingStore>(sp =>
    new ConsentBridgePersonPendingStore(sp.GetRequiredService<ConsentStore>(), demoRoles, demoGroups));

// Mission governance (§PS Governance Endpoints). AddAAuthGovernance registers
// the in-memory mission store + log; the PS supplies the policy/user-channel
// seams (decider / audit sink / interaction relay), the deterministic consent
// script that stands in for a real user-consent screen, and the out-of-scope
// mission-token decision (ScriptMissionTokenConsent — the SDK's clarification
// protocol calls into it).
builder.Services.AddAAuthGovernance();
builder.Services.AddSingleton<MissionConsentScript>();
builder.Services.AddSingleton<MissionPolicyStore>();
builder.Services.AddSingleton<MissionPendingStore>();
builder.Services.AddSingleton<IMissionTokenConsent>(sp =>
    new ScriptMissionTokenConsent(
        sp.GetRequiredService<MissionPolicyStore>(), sp.GetRequiredService<MissionConsentScript>()));
builder.Services.AddSingleton<IPermissionDecider, SamplePermissionDecider>();
builder.Services.AddSingleton<IAuditSink, SampleAuditSink>();
builder.Services.AddSingleton<IInteractionRelay, SampleInteractionRelay>();
builder.Services.AddSingleton(sp =>
    new UpstreamTokenValidator(
        sp.GetRequiredService<MetadataClient>(),
        sp.GetRequiredService<JwksClient>()));

// Four-party federation client (PS→AS), wired by the SDK: the PS signs the
// token request with its own key via the `jwks_uri` scheme, and the transport
// uses the named federation client so tests can route it to an in-process AS.
builder.Services.AddAAuthFederation(psKey, psIssuer, PsKid);

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints — served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------

// JWKS (reused from the shared resource helper — same shape).
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = psIssuer,
    Name = "Mock Person Server",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [PsScope] = "Issue AAuth auth tokens for the Calendar",
        [PsAdminScope] = "Issue elevated (write) AAuth auth tokens for the Calendar",
    },
    SignatureWindow = signatureWindowSeconds,
});

// Person Server token endpoint + pending polls + PS metadata, in one call. The
// SDK owns verification, the three-/four-party mint, PS→AS federation, and the
// mission three-gate + clarification protocol; the decision seams registered
// above supply the demo's policy. `/admin` is the PS's own unsigned consent
// surface (§PS Approval Endpoint Authentication — out of scope), so the mapper
// skips signature verification for it.
app.MapAAuthPersonServer(new AAuthPersonServerOptions
{
    Issuer = psIssuer,
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    DefaultScope = PsScope,
    TrustedAccessServers = trustedAccessServers,
    // Governance endpoints (mapped below) advertised in aauth-person.json so the
    // agent's MissionClient / PermissionClient / AuditClient can resolve them.
    MissionEndpoint = $"{psIssuer.TrimEnd('/')}/mission",
    PermissionEndpoint = $"{psIssuer.TrimEnd('/')}/permission",
    AuditEndpoint = $"{psIssuer.TrimEnd('/')}/audit",
    InteractionEndpoint = $"{psIssuer.TrimEnd('/')}/mission-interaction",
    UnsignedPathPrefixes = new[] { "/admin" },
});

// -----------------------------------------------------------------------
// Mission governance endpoints (§PS Governance Endpoints). All four are
// -----------------------------------------------------------------------
// Mission governance endpoints (§PS Governance Endpoints). All four are
// behind AAuth verification (signed agent-token requests); they sit on
// distinct paths from the browser `/interaction` consent page so they are
// not excluded from verification. User decisions come from the scripted
// MissionConsentScript (the mock's stand-in for a consent screen).
// -----------------------------------------------------------------------

// mission_endpoint (§Mission Creation): the agent proposes a mission; the PS
// records the approved mission and returns the verbatim approval blob plus the
// `AAuth-Mission` header whose `s256` the agent verifies.
app.MapPost("/mission", async (
    HttpContext ctx,
    IMissionStore missions,
    MissionPolicyStore policy,
    MissionConsentScript script,
    MissionPendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    if (ctx.GetAAuthTokenType() != AAuthTokenType.AgentToken)
    {
        return Results.Json(new { error = "invalid_carrier_token" }, statusCode: StatusCodes.Status403Forbidden);
    }
    var agentId = (string?)parsed.Payload?["sub"];
    if (string.IsNullOrEmpty(agentId))
    {
        return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" }, statusCode: StatusCodes.Status403Forbidden);
    }

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    MissionProposal proposal;
    try
    {
        proposal = GovernanceEndpoints.ParseMissionProposal(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (!script.ApproveMissionProposal)
    {
        return Results.Json(new { error = "denied" }, statusCode: StatusCodes.Status403Forbidden);
    }

    // Interactive mode (§Mission Creation): mission approval is the most
    // important consent in the model, so park the proposal and let the user
    // approve it on the PS browser screen — the same deferred (202) path the
    // token and permission gates use. The agent's MissionClient polls the
    // pending URL and receives the signed approval blob once the user decides.
    if (script.InteractiveBrowser)
    {
        var pendingMission = pending.Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Mission,
            AgentId = agentId,
            S256 = string.Empty,            // computed from the blob once approved
            Approver = psIssuer,
            Proposal = proposal,
        });
        ctx.Response.Headers.Location = $"/mission-create-pending/{pendingMission.Id}";
        // Human approval takes seconds — poll at ~1s, not the 100ms floor a 0 clamps to.
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", pendingMission.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    // The demo approves every proposed tool; a real PS would let the user prune them.
    var approvedTools = proposal.Tools;
    var (blob, s256) = MissionApprovalBuilder.Build(psIssuer, agentId, proposal, approvedTools, DateTimeOffset.UtcNow);

    await missions.SaveAsync(new StoredMission(s256, psIssuer, agentId, blob));
    policy.Record(s256, proposal.Description, approvedTools, script.InScopeSnapshot());

    ctx.Response.Headers[AAuthMissionHeader.Name] =
        AAuthMissionHeader.FormatStructured(psIssuer, s256);
    return Results.Bytes(blob, "application/json");
});

// Interactive mission-creation resolution (§Mission Creation). The agent polls
// here while the user approves or declines the proposed mission in the browser.
// On approval the PS builds and stores the verbatim approval blob and returns it
// with the AAuth-Mission header — exactly what the synchronous path returns.
app.MapGet("/mission-create-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending,
    IMissionStore missions, MissionPolicyStore policy, MissionConsentScript script) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Mission)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    // Hold at 202 until the user decides on the browser consent screen.
    if (entry.Decision is null)
    {
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    pending.Remove(id);
    if (!entry.Decision.Value)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "denied", detail = "the user declined this mission" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var proposal = entry.Proposal!;
    // The demo approves every proposed tool; a real PS would let the user prune them.
    var approvedTools = proposal.Tools;
    var (blob, s256) = MissionApprovalBuilder.Build(psIssuer, entry.AgentId, proposal, approvedTools, DateTimeOffset.UtcNow);
    await missions.SaveAsync(new StoredMission(s256, psIssuer, entry.AgentId, blob));
    policy.Record(s256, proposal.Description, approvedTools, script.InScopeSnapshot());
    ctx.Response.Headers[AAuthMissionHeader.Name] =
        AAuthMissionHeader.FormatStructured(psIssuer, s256);
    return Results.Bytes(blob, "application/json");
});

// permission_endpoint (§Permission Endpoint): the agent asks whether an action
// is permitted. A pre-approved tool is granted silently; anything else is parked
// (202) and resolved by the (scripted) user decision on the pending URL.
app.MapPost("/permission", async (
    HttpContext ctx,
    IMissionStore missions,
    IMissionLog log,
    IPermissionDecider decider,
    MissionConsentScript script,
    MissionPendingStore pending) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var agentId = (string?)parsed.Payload?["sub"] ?? string.Empty;

    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    PermissionRequest request;
    try
    {
        request = GovernanceEndpoints.ParsePermission(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    StoredMission? stored = null;
    IReadOnlyList<MissionLogEntry> history = [];
    if (request.Mission is not null)
    {
        stored = await missions.GetAsync(request.Mission.S256);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }
        history = await log.ReadAsync(request.Mission.S256);
    }

    var decision = await decider.DecideAsync(new PermissionDecisionContext(request, stored, history));

    // Prompt -> park the request and let the agent poll while the user decides.
    if (decision.Outcome == PermissionOutcome.Prompt && request.Mission is not null)
    {
        var entry = pending.Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Permission,
            AgentId = agentId,
            S256 = request.Mission.S256,
            Approver = request.Mission.Approver,
            Action = request.Action.Name,
        });
        ctx.Response.Headers.Location = $"/permission-pending/{entry.Id}";
        // Human approval takes seconds — poll at ~1s, not the 100ms floor a 0 clamps to.
        ctx.Response.Headers["Retry-After"] = "1";
        ctx.Response.Headers["Cache-Control"] = "no-store";
        // Interactive mode points the user at the PS browser page to decide.
        if (script.InteractiveBrowser)
        {
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
        }
        return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    var granted = decision.Outcome == PermissionOutcome.Granted;
    if (request.Mission is not null)
    {
        await log.AppendAsync(new MissionLogEntry(
            request.Mission.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
        {
            Action = request.Action.Name,
            Granted = granted,
            Detail = decision.Reason.ToString(),
        });
    }

    return Results.Json(new
    {
        permission = granted ? "granted" : "denied",
        reason = decision.Message ?? decision.Reason.ToString(),
    });
});

// audit_endpoint (§Audit Endpoint): the agent reports an action it took.
app.MapPost("/audit", async (
    HttpContext ctx,
    IMissionStore missions,
    IAuditSink sink) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    AuditRecord record;
    try
    {
        record = GovernanceEndpoints.ParseAudit(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    var stored = await missions.GetAsync(record.Mission.S256);
    if (stored is { State: MissionState.Terminated })
    {
        return GovernanceEndpoints.MissionTerminated();
    }

    await sink.RecordAsync(record);
    return Results.StatusCode(StatusCodes.Status201Created);
});

// interaction_endpoint (§Interaction Endpoint): questions and completion
// proposals relayed to the user. A completion the user accepts terminates the
// mission; otherwise the mission stays active.
app.MapPost("/mission-interaction", async (
    HttpContext ctx,
    IMissionStore missions,
    IMissionLog log,
    IInteractionRelay relay) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    if (body is null)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    InteractionRequest request;
    try
    {
        request = GovernanceEndpoints.ParseInteraction(body);
    }
    catch (FormatException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (request.Mission is not null)
    {
        var stored = await missions.GetAsync(request.Mission.S256);
        if (stored is { State: MissionState.Terminated })
        {
            return GovernanceEndpoints.MissionTerminated();
        }
    }

    var result = await relay.RelayAsync(request);

    if (request.Mission is not null)
    {
        await log.AppendAsync(new MissionLogEntry(
            request.Mission.S256, MissionLogEntryKind.Interaction, DateTimeOffset.UtcNow)
        {
            Detail = request.Type.ToString(),
        });
    }

    switch (request.Type)
    {
        case InteractionType.Question:
            return Results.Json(new { answer = result.Answer ?? string.Empty });

        case InteractionType.Completion:
            // The user accepted completion -> terminate the mission (§Mission Management).
            if (result.Accepted == true && request.Mission is not null)
            {
                await missions.SetStateAsync(request.Mission.S256, MissionState.Terminated);
                return Results.Json(new { mission_status = "terminated" });
            }
            return Results.Json(new { mission_status = "active" });

        default:
            return Results.Json(new { status = "ok" });
    }
});

// Non-pre-approved permission resolution (§Permission Endpoint). The poll
// returns the (scripted) user decision.
app.MapGet("/permission-pending/{id}", async (
    HttpContext ctx, string id, MissionPendingStore pending,
    IMissionLog log, MissionConsentScript script) =>
{
    var entry = pending.Get(id);
    if (entry is null || entry.Kind != MissionPendingKind.Permission)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }
    // Interactive mode: hold at 202 until the user decides in the browser.
    bool granted;
    if (script.InteractiveBrowser)
    {
        if (entry.Decision is null)
        {
            ctx.Response.Headers["Retry-After"] = "1";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers[AAuthRequirementHeader.Name] =
                Interaction.Format($"{psIssuer.TrimEnd('/')}/interaction", entry.Id);
            return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
        }
        granted = entry.Decision.Value;
    }
    else
    {
        granted = script.ApprovePermission;
    }
    await log.AppendAsync(new MissionLogEntry(
        entry.S256, MissionLogEntryKind.Permission, DateTimeOffset.UtcNow)
    {
        Action = entry.Action,
        Granted = granted,
        Detail = "OutOfScope",
    });
    pending.Remove(id);
    return Results.Json(new
    {
        permission = granted ? "granted" : "denied",
        reason = granted ? "OutOfScope" : "the user denied this action.",
    });
});

// -----------------------------------------------------------------------
// DEMO-ONLY admin endpoints. A real PS would NEVER expose unauthenticated
// consent flips. These exist so the GuidedTour's "User approves" button
// and the §3.4 user-consent integration test can drive the consent
// transition deterministically. Body shape:
//   { "agent": "aauth:...@...", "resource": "https://calendar/", "scope": "calendar.read" }
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
// resetConsent helper). A production PS would never expose this. The SDK-owned
// token pending entries are id-keyed + TTL-evicted, so clearing the demo
// ConsentStore + mission stores is enough to re-baseline.
app.MapPost("/admin/reset", (ConsentStore consent, MissionPendingStore missionPending, MissionConsentScript script) =>
{
    consent.Clear();
    missionPending.Clear();
    script.Reset();
    return Results.Ok(new { ok = true });
});

// DEMO-ONLY: script the next mission-governance decisions (option A). The
// CLI/E2E harness POSTs here before driving the agent so each Consent-Matrix
// outcome is reproducible. A real PS resolves these through a live user-consent
// screen. Body (all optional): { reset, approveMission, approveToken,
// approvePermission, questionAnswer, acceptCompletion, interactive,
// inScope: [{resource, scope}] }.
app.MapPost("/admin/mission-script", async (HttpContext ctx, MissionConsentScript script) =>
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    body ??= [];

    if ((bool?)body["reset"] == true) { script.Reset(); }
    if (body["approveMission"] is JsonValue am) { script.ApproveMissionProposal = am.GetValue<bool>(); }
    if (body["approveToken"] is JsonValue at) { script.ApproveOutOfScopeToken = at.GetValue<bool>(); }
    if (body["approvePermission"] is JsonValue ap) { script.ApprovePermission = ap.GetValue<bool>(); }
    if (body["questionAnswer"] is JsonValue qa) { script.QuestionAnswer = qa.GetValue<string>(); }
    if (body["acceptCompletion"] is JsonValue ac) { script.AcceptCompletion = ac.GetValue<bool>(); }
    if (body["requireClarification"] is JsonValue rc) { script.RequireTokenClarification = rc.GetValue<bool>(); }
    if (body["clarificationQuestion"] is JsonValue cq) { script.ClarificationQuestion = cq.GetValue<string>(); }
    if (body["interactive"] is JsonValue iv) { script.InteractiveBrowser = iv.GetValue<bool>(); }
    if (body["inScope"] is JsonArray inScope)
    {
        foreach (var item in inScope.OfType<JsonObject>())
        {
            var resource = (string?)item["resource"];
            var scope = (string?)item["scope"];
            if (!string.IsNullOrEmpty(resource) && !string.IsNullOrEmpty(scope))
            {
                script.SeedInScope(resource, scope);
            }
        }
    }
    return Results.Ok(new { ok = true });
});

// DEMO-ONLY: terminate a mission by its s256 (§Mission Management). After this
// the PS rejects token/permission/audit/interaction requests for the mission
// with `mission_terminated`. Body: { s256 }.
app.MapPost("/admin/mission-terminate", async (HttpContext ctx, IMissionStore missions, MissionPolicyStore policy) =>
{
    JsonObject? body;
    try { body = await ctx.Request.ReadFromJsonAsync<JsonObject>(); }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: StatusCodes.Status400BadRequest);
    }
    var s256 = (string?)body?["s256"];
    if (string.IsNullOrEmpty(s256))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing s256" }, statusCode: StatusCodes.Status400BadRequest);
    }
    await missions.SetStateAsync(s256, MissionState.Terminated);
    policy.Remove(s256);
    return Results.Ok(new { ok = true, s256, mission_status = "terminated" });
});

// DEMO-ONLY: read a mission's ordered log/trail by its s256 (§Mission Log). The
// PS holds the authoritative record of every governed step under the mission —
// tokens, permissions, clarifications, audits, interactions. Samples surface
// this to show the auditable trail a mission accrues. Returns { s256, entries:[…] }.
app.MapGet("/admin/mission-log/{s256}", async (string s256, IMissionLog log) =>
{
    var entries = await log.ReadAsync(s256);
    return Results.Ok(new
    {
        s256,
        entries = entries.Select(e => new
        {
            kind = e.Kind.ToString().ToLowerInvariant(),
            timestamp = e.Timestamp,
            resource = e.Resource,
            scope = e.Scope,
            action = e.Action,
            granted = e.Granted,
            detail = e.Detail,
        }).ToArray(),
    });
});

// User-facing interaction page. The 202 from `POST /token` told the
// agent's user to visit this URL with `?code={pending-id}`. In a real PS
// this page would be behind the user's signed-in browser session
// (cookie/passkey/SSO); here we trust the demo environment and just look
// up the pending entry by its single-use code. The form submits to
// /interaction/approve or /interaction/deny.
app.MapGet("/interaction", (string? code, IPersonPendingStore pending, MissionPendingStore missionPending, MissionPolicyStore missionPolicy) =>
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

    // A mission token / permission prompt (§Missions) takes priority — these
    // single-use codes are the mission-pending entry ids.
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        // Mission creation shows the proposal itself; the token/permission gates
        // show the request plus the mission it sits under (§Mission Creation).
        var isCreation = mission.Kind == MissionPendingKind.Mission;
        var description = isCreation ? mission.Proposal!.Description : missionPolicy.Describe(mission.S256);
        var approvedTools = isCreation
            ? (IReadOnlyCollection<string>)mission.Proposal!.Tools.Select(t => t.Name).ToArray()
            : missionPolicy.ApprovedTools(mission.S256);
        // Resource scopes (§Scopes) authorize access to a remote *resource* and
        // are carried in auth tokens; tools (§Permission Endpoint) are *local*
        // actions the agent runs itself. A mission proposal contains NO scopes —
        // the agent proposes only a description + tools, and the PS evaluates
        // each scope request lazily, per token request, over the mission's life
        // (§Mission Creation, §Scopes). So the creation screen lists no scopes;
        // the token/permission gates show the scopes consented so far.
        var inScopePairs = isCreation
            ? (IReadOnlyCollection<string>)Array.Empty<string>()
            : missionPolicy.InScopePairs(mission.S256);
        var what = mission.Kind switch
        {
            MissionPendingKind.Token =>
                "<div class=req><div class=req-h>This request</div>"
                + $"<div class=row><b>Resource:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Resource)}</code></div>"
                + $"<div class=row><b>Scope:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Scope)}</code></div>"
                + "<div class=req-n>Not yet covered by this mission — approve to grant this scope (the agent may reuse it for the rest of the mission).</div></div>",
            MissionPendingKind.Permission =>
                "<div class=req><div class=req-h>This request</div>"
                + $"<div class=row><b>Tool:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.Action)}</code></div>"
                + "<div class=req-n>A tool that is not pre-approved on the mission — approve to allow this call.</div></div>",
            _ => string.Empty,
        };
        // The mission claim binds requests to a thumbprint (s256); surface the
        // human-readable description the user approved so they can decide in
        // context, with the s256 shown only as a verifiable reference. At
        // creation time the s256 does not exist yet, so show only the prose.
        var missionLine = isCreation
            ? $"<div class=row><b>Mission:</b> <span>{System.Net.WebUtility.HtmlEncode(description)}</span></div>"
            : description is not null
                ? $"<div class=row><b>Mission:</b> <span>{System.Net.WebUtility.HtmlEncode(description)}</span></div>"
                  + $"<div class=row><b></b> <code style='font-size:.8rem;color:#888'>{System.Net.WebUtility.HtmlEncode(mission.S256)}</code></div>"
                : $"<div class=row><b>Mission:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.S256)}</code></div>";
        // Show the mission's resource scopes and pre-approved tools (§Scopes vs
        // §Permission Endpoint) so the user sees the authority this request sits
        // under. A mission proposal lists NO scopes, so at creation we show no
        // scope list — only a note that the PS will judge each scope request
        // against the mission as it arrives. On the token/permission gates the
        // user is here precisely BECAUSE this scope/tool is not yet covered
        // (gate 3, §Agent Token Request), so we show what has already been
        // granted this mission as context for the new decision — not as the
        // thing being requested now.
        var scopesLine = isCreation
            ? string.Empty
            : inScopePairs.Count > 0
                ? $"<div class=row><b>Granted&nbsp;so&nbsp;far:</b> <code>{System.Net.WebUtility.HtmlEncode(string.Join(", ", inScopePairs))}</code></div>"
                : "<div class=row><b>Granted&nbsp;so&nbsp;far:</b> <span style='color:#888'>nothing yet — this is the first request</span></div>";
        // At creation the agent proposed only a description + tools (§Mission
        // Creation) — it did NOT request scopes, and the PS does not enumerate
        // them up front. Tell the user the PS will determine the scopes the
        // mission needs from its description, request by request, as the agent
        // works (§Scopes — "The PS evaluates requested scopes against mission
        // context").
        var scopesNote = isCreation
            ? "<div class=req-n style='margin:.2rem 0 .4rem 0'>This mission grants no scopes up front. The Person Server will determine the resource scopes it needs from the mission description, judging each request as the agent makes it — granting silently if it fits the intent, or asking you otherwise.</div>"
            : string.Empty;
        var toolsLabel = isCreation ? "Tools" : "Approved&nbsp;tools";
        var toolsLine = approvedTools.Count > 0
            ? $"<div class=row><b>{toolsLabel}:</b> <code>{System.Net.WebUtility.HtmlEncode(string.Join(", ", approvedTools))}</code></div>"
            : $"<div class=row><b>{toolsLabel}:</b> <span style='color:#888'>(none)</span></div>";
        // A short, spec-grounded note defining the two kinds of authority so the
        // user understands what they are approving (§Scopes, §Permission Endpoint).
        var defn =
            "<div class=defn>"
            + "<div><b>Resource scope</b> — access to a remote <i>resource</i> (e.g. an API), granted via an auth token. "
            + "The resource defines its scopes; the Person Server determines which a mission needs from its intent.</div>"
            + "<div><b>Tool</b> — a <i>local</i> action the agent runs itself (a tool call, file write, message). "
            + "No resource is involved; the Person Server governs it through this permission step.</div>"
            + "</div>";
        var heading = isCreation
            ? "An agent wants to start a new mission"
            : $"An agent is requesting {(mission.Kind == MissionPendingKind.Token ? "access" : "permission")} under its mission";
        var intro = isCreation
            ? "The agent proposed a durable <b>mission</b> and the <b>tools</b> it wants to run. As the agent works, the Person Server will determine the resource <b>scopes</b> it needs from the mission description, judging each request in context. Approve to start the mission; every later request is checked against it."
            : "This request falls <b>outside</b> the agent's pre-approved mission scope, so the Person Server is asking you to decide.";
        var missionHtml =
            "<!doctype html><meta charset=utf-8><title>Approve a mission request — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}"
            + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
            + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:7rem;color:#555}"
            + ".req{margin:1rem 0;padding:.6rem .85rem;background:#faf5ff;border:1px solid #e9d5ff;border-radius:.4rem}"
            + ".req-h{font-weight:600;color:#6b21a8;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;margin-bottom:.35rem}"
            + ".req-n{color:#777;font-size:.82rem;margin-top:.35rem}"
            + ".defn{margin:1.25rem 0 .5rem;padding:.6rem .85rem;background:#f8fafc;border:1px solid #e2e8f0;"
            + "border-radius:.4rem;font-size:.82rem;color:#555;display:flex;flex-direction:column;gap:.4rem}"
            + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
            + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
            + "button.approve{background:#6ee7b7;border-color:#34d399}"
            + "button.deny{background:#fecaca;border-color:#f87171}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<div class=sub>localhost:5100 — overseeing what this agent does under its mission</div>"
            + $"<h1>{heading}</h1>"
            + $"<p>{intro}</p>"
            + $"<div class=row><b>Agent:</b> <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code></div>"
            + missionLine
            + scopesLine
            + scopesNote
            + toolsLine
            + what
            + defn
            + "<form method=post action=\"/interaction/approve\">"
            + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
            + "<button class=approve type=submit>Approve</button>"
            + "</form>"
            + "<form method=post action=\"/interaction/deny\">"
            + $"<input type=hidden name=code value=\"{System.Net.WebUtility.HtmlEncode(code)}\">"
            + "<button class=deny type=submit>Deny</button>"
            + "</form>";
        return Results.Content(missionHtml, contentType: "text/html");
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
        "<!doctype html><meta charset=utf-8><title>Approve agent at the Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}"
        + ".sub{color:#777;font-size:.85rem;margin:.35rem 0 1.25rem}"
        + "h1{font-size:1.25rem}.row{display:flex;gap:.5rem;margin:.25rem 0}.row b{min-width:6rem;color:#555}"
        + "form{margin-top:1.5rem;display:inline-flex;gap:.75rem}"
        + "button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;border-radius:.25rem;border:1px solid #999}"
        + "button.approve{background:#6ee7b7;border-color:#34d399}"
        + "button.deny{background:#fecaca;border-color:#f87171}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<div class=sub>localhost:5100 — the server that holds your resources and standing consent</div>"
        + "<h1>An agent is requesting access on your behalf</h1>"
        + "<p>This is the <b>Person Server's</b> consent screen. In a real PS you would be signed in via cookie / passkey / SSO before reaching here.</p>"
        + $"<div class=row><b>Agent:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.AgentId)}</code></div>"
        + $"<div class=row><b>Resource:</b> <code>{System.Net.WebUtility.HtmlEncode(entry.ResourceUrl)}</code></div>"
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
app.MapPost("/interaction/approve", async (HttpContext ctx, ConsentStore consent, IPersonPendingStore pending, MissionPendingStore missionPending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    // Mission creation / permission prompt: record the user's approval so the
    // agent's next poll resolves to a granted decision (§Missions).
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        mission.Decision = true;
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Approved — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<h1>Approved</h1>"
            + $"<p>You approved <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code>'s mission request. The agent will proceed on its next poll.</p>"
            + "<p>You can close this tab.</p>",
            contentType: "text/html");
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    // An out-of-scope mission token request (held interactively) resolves by
    // marking the SDK-owned pending decision allowed with the demo identity; a
    // plain three-party request records standing consent (the bridge mints).
    if (entry.MissionGate)
    {
        var isAdmin = SampleIdentityClaimsAsserter.IsAdminAgent(entry.AgentId);
        pending.MarkAllowed(code, "pairwise-sub", tenant: null,
            roles: isAdmin ? demoRoles : null, groups: isAdmin ? demoGroups : null);
    }
    else
    {
        consent.Grant(entry.AgentId, entry.ResourceUrl, entry.Scope);
    }
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Approved — Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<h1>Approved</h1>"
        + $"<p>You granted <code>{System.Net.WebUtility.HtmlEncode(entry.AgentId)}</code> access to "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.ResourceUrl)}</code> with scope "
        + $"<code>{System.Net.WebUtility.HtmlEncode(entry.Scope)}</code> at the <b>Person Server</b>.</p>"
        + "<p>You can close this tab — the agent will receive its auth token on its next poll.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

// Deny handler. Marks the pending entry as denied (rather than removing
// it) so the agent's next poll receives a deterministic
// `403 denied` instead of an ambiguous `404 unknown_pending`.
app.MapPost("/interaction/deny", async (HttpContext ctx, IPersonPendingStore pending, MissionPendingStore missionPending) =>
{
    var code = (await ctx.Request.ReadFormAsync())["code"].ToString();
    if (string.IsNullOrEmpty(code))
    {
        return Results.BadRequest(new { error = "invalid_request", detail = "missing 'code'" });
    }
    // Mission creation / permission prompt: record the user's denial so the
    // agent's next poll resolves to a denied decision (§Missions).
    var mission = missionPending.Get(code);
    if (mission is not null)
    {
        mission.Decision = false;
        return Results.Content(
            "<!doctype html><meta charset=utf-8><title>Denied — Person Server</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#7c3aed;color:#fff;"
            + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
            + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#ddd6fe}</style>"
            + "<div class=badge><span class=dot></span>Person Server — mission governance</div>"
            + "<h1>Denied</h1>"
            + $"<p>You denied <code>{System.Net.WebUtility.HtmlEncode(mission.AgentId)}</code>'s mission request. The agent's next poll will receive <code>403 denied</code>.</p>"
            + "<p>You can close this tab.</p>",
            contentType: "text/html");
    }
    var entry = pending.Get(code);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_code", code });
    }
    pending.MarkDenied(code, "the user denied this request");
    return Results.Content(
        "<!doctype html><meta charset=utf-8><title>Denied — Person Server</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;"
        + "padding:.4rem .8rem;border-radius:.4rem;font-weight:600;letter-spacing:.02em}"
        + ".badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}</style>"
        + "<div class=badge><span class=dot></span>Person Server</div>"
        + "<h1>Denied</h1>"
        + $"<p>You denied <code>{System.Net.WebUtility.HtmlEncode(entry.AgentId)}</code>'s request at the <b>Person Server</b>. The agent's next poll will receive <code>403 denied</code>.</p>"
        + "<p>You can close this tab.</p>",
        contentType: "text/html");
}).DisableAntiforgery();

app.Run();

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
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
// because the resource-server samples also declare their own global `Program`,
// and adding both project references to a test assembly would make `Program`
// ambiguous. A dedicated, namespaced marker sidesteps that.
namespace MockPersonServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
