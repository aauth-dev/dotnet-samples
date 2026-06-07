using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Orchestrator;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Orchestrator identity: acts as both a resource AND an agent.
// Generates its own signing key on startup (demo only).
// -----------------------------------------------------------------------
var orchestratorKey = AAuthKey.Generate();
const string OrchestratorKid = "orch-1";
const string OrchestratorScope = "orchestrate";
var orchestratorUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5200";
var downstreamUrl = builder.Configuration["AAuth:Downstream"] ?? "http://localhost:5000";
var psUrl = builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100";
var agentId = builder.Configuration["AAuth:AgentId"] ?? "aauth:orchestrator@localhost:5200";

builder.Services.AddSingleton(orchestratorKey);
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<PendingStore>();
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");
builder.Services.AddHttpClient();

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints: resource metadata + agent metadata + JWKS
// -----------------------------------------------------------------------
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = orchestratorUrl,
    ClientName = "Orchestrator Demo",
    SigningKeys = new Dictionary<string, AAuthKey> { [OrchestratorKid] = orchestratorKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [OrchestratorScope] = "Orchestrate calls to downstream resources",
    },
});

// Agent metadata: downstream resources discover this to verify our identity.
app.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
{
    Issuer = orchestratorUrl,
    ClientName = "Orchestrator Demo",
    SigningKeys = new Dictionary<string, AAuthKey> { [OrchestratorKid] = orchestratorKey },
});

// -----------------------------------------------------------------------
// Self-issued agent identity: per §Call Chaining Identity, the Orchestrator
// is its own AP — it self-issues agent tokens signed by its own key.
// This ensures agent_token.iss == resource URL, satisfying §Upstream Token
// Verification step 3 (aud in upstream_token matches intermediary resource).
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Verification + Challenge middleware: validates the HTTP signature,
// verifies the JWT issuer, and auto-challenges agent tokens with a
// resource token requiring an auth token for access.
// -----------------------------------------------------------------------
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthIntermediary(
        new AAuthVerificationOptions
        {
            ResourceIdentifier = orchestratorUrl,
            RequireIssuerVerification = true,
            TrustedAuthTokenIssuers = new HashSet<string> { psUrl },
        },
        new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = orchestratorKey,
            ResourceKeyId = OrchestratorKid,
            ResourceIdentifier = orchestratorUrl,
            DefaultScopes = OrchestratorScope,
            // Mission-aware: when an AAuth-Mission header is present, copy the
            // {approver, s256} into the resource token so the PS governs the
            // agent→orchestrator exchange under the mission (§Mission Context at
            // Resources). A no-op when no mission header is present, so the plain
            // call chain ("/" → "/jwt") is unaffected.
            MissionAware = true,
        }));

// -----------------------------------------------------------------------
// GET / — Orchestrator endpoint (call chaining via WithCallChaining).
//
// The middleware handles verification + 401 challenge automatically.
// Only auth-token callers reach this handler. The downstream client routes
// the exchange to the correct PS/AS using the upstream auth token.
//
// Interaction Chaining (AAuth §Interaction Chaining): the Orchestrator has no
// user of its own, so it CANNOT relay a downstream consent prompt. Its
// OnInteractionRequired callback therefore throws
// AAuthInteractionChainedException, which aborts the in-flight exchange before
// it blocks-polls. The handler catches it, parks a pending entry, and re-emits
// its OWN 202 + requirement=interaction to the caller (passing through the PS's
// interaction url/code, swapping only Location for its own pending URL).
// -----------------------------------------------------------------------

// Run the downstream chained call with the given upstream auth token. Returns
// the combined chain result on success; throws AAuthInteractionChainedException
// when the downstream PS defers for user consent, or
// AAuthInteractionDeniedException when the user denied.
// Run the downstream chained call with the given upstream auth token. Returns
// the combined chain result on success; throws AAuthInteractionChainedException
// when the downstream PS defers for user consent, or
// AAuthInteractionDeniedException when the user denied. <paramref name="downstreamPath"/>
// selects the downstream resource path — "/jwt" for the plain chain or the
// mission-aware "/jwt/mission" for a mission-governed chain (§Mission Context at
// Resources). When the upstream auth token carries a mission, WithCallChaining
// auto-forwards the AAuth-Mission header (via MissionForwardingHandler) and routes
// the exchange to mission.approver, so the mission governs every hop (§Call Chaining).
async Task<IResult> RunChainAsync(HttpContext ctx, string upstreamToken, string downstreamPath)
{
    // Self-issued agent token (iss = orchestratorUrl) satisfies §Upstream Token
    // Verification step 3 — the PS can match upstream_token.aud against iss.
    //
    // Mission governance composes with call chaining (AAuth §Agent Governance,
    // §Call Chaining): if the upstream auth token carries `mission.approver`,
    // WithCallChaining auto-forwards the `AAuth-Mission` header (via
    // MissionForwardingHandler) and routes to mission.approver. The mission-aware
    // downstream path then re-binds the mission into the next resource_token, so a
    // single mission governs the whole chain. With no mission present this same
    // handler follows §Call Chaining's "No mission, iss is a PS" path unchanged.
    using var downstream = AAuthClientBuilder.SelfIssuing(orchestratorKey)
        .As(orchestratorUrl, agentId)
        .WithKid(OrchestratorKid)
        .WithPersonServer(psUrl)
        .WithCallChaining(upstreamToken)
        .WithChallengeHandling(opts =>
        {
            // No user to relay to → chain instead of relay. The throw unwinds
            // the exchange before DeferredPoller blocks; the endpoint catches it.
            opts.OnInteractionRequired = (interaction, _)
                => throw new AAuthInteractionChainedException(interaction);
            // Do NOT declare the "interaction" capability: we cannot relay an
            // interaction to a user, we chain it (§AAuth-Capabilities).
            opts.Capabilities = Array.Empty<string>();
        })
        .Build();

    var response = await downstream.GetAsync($"{downstreamUrl.TrimEnd('/')}{downstreamPath}");
    var body = await response.Content.ReadAsStringAsync();
    JsonNode? downstreamJson = null;
    try { downstreamJson = JsonNode.Parse(body); } catch { }

    var upstreamResult = ctx.GetAAuthVerification();
    return Results.Ok(new
    {
        chain = "Agent → Orchestrator → WhoAmI",
        upstream = new
        {
            scheme = upstreamResult?.Scheme,
            agent = upstreamResult?.Agent,
            tokenType = upstreamResult?.TokenType,
        },
        orchestrator = new
        {
            identity = agentId,
            action = "call-chained to downstream with upstream_token",
        },
        downstream = downstreamJson,
    });
}

// Re-emit the Orchestrator's own 202 requirement=interaction for a parked
// chained request: its own Location (the pending URL, keyed by the entry's
// poll-route prefix), the PS's pass-through interaction url/code. Spec
// §Interaction Chaining + §Deferred Responses.
IResult ReEmitChainedInteraction(HttpContext ctx, PendingStore.Entry entry)
{
    ctx.Response.Headers.Location = $"{entry.PendingPrefix}/{entry.Id}";
    ctx.Response.Headers["Retry-After"] = "1";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    ctx.Response.Headers[AAuthRequirementHeader.Name] =
        Interaction.Format(entry.InteractionUrl, entry.InteractionCode);
    return Results.Json(new { status = "interaction_required" }, statusCode: StatusCodes.Status202Accepted);
}

app.MapGet("/", async (HttpContext ctx, PendingStore pending) =>
{
    var upstreamToken = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (string.IsNullOrEmpty(upstreamToken))
    {
        return Results.Json(
            new { error = "invalid_request", detail = "missing upstream auth token" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    try
    {
        return await RunChainAsync(ctx, upstreamToken, "/jwt");
    }
    catch (AAuthInteractionChainedException ex)
    {
        // Downstream needs the user's consent. Park it and chain the 202 up.
        var entry = pending.Add(upstreamToken, ex.Interaction.Url, ex.Interaction.Code);
        return ReEmitChainedInteraction(ctx, entry);
    }
});

// GET /mission — the mission-governed twin of "/". Identical chaining, but the
// downstream hop targets WhoAmI's mission-aware "/jwt/mission" so a mission
// present in the upstream auth token is forwarded and re-bound at each hop
// (§Mission Context at Resources, §Call Chaining).
app.MapGet("/mission", async (HttpContext ctx, PendingStore pending) =>
{
    var upstreamToken = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (string.IsNullOrEmpty(upstreamToken))
    {
        return Results.Json(
            new { error = "invalid_request", detail = "missing upstream auth token" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    try
    {
        return await RunChainAsync(ctx, upstreamToken, "/jwt/mission");
    }
    catch (AAuthInteractionChainedException ex)
    {
        var entry = pending.Add(
            upstreamToken, ex.Interaction.Url, ex.Interaction.Code,
            downstreamPath: "/jwt/mission", pendingPrefix: "/mission-pending");
        return ReEmitChainedInteraction(ctx, entry);
    }
});

// -----------------------------------------------------------------------
// GET /pending/{id} — the caller polls here while its user approves the
// downstream consent at the PS interaction page. Signed + auth-token gated by
// the same middleware as "/". Each poll RE-DRIVES the chained call with the
// stored upstream token (idempotent; consent is keyed by agent/resource/scope
// at the PS). Returns:
//   * 202 + same requirement=interaction while still unconsented downstream
//   * 200 + combined chain result once the downstream auth token resolves
//   * 403 denied if the user denied
//   * 404 if the pending id is unknown
// -----------------------------------------------------------------------
app.MapGet("/pending/{id}", async (HttpContext ctx, string id, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    try
    {
        var result = await RunChainAsync(ctx, entry.UpstreamToken, entry.DownstreamPath);
        pending.Remove(id); // resolved — drop the parked entry
        return result;
    }
    catch (AAuthInteractionChainedException)
    {
        // Still unconsented downstream — re-emit our own 202 (same url/code:
        // PS consent is keyed by the triple, so the original page still works).
        return ReEmitChainedInteraction(ctx, entry);
    }
    catch (AAuthInteractionDeniedException)
    {
        pending.Remove(id);
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "denied", detail = "the user denied this request" },
            statusCode: StatusCodes.Status403Forbidden);
    }
});

// GET /mission-pending/{id} — the mission chain's poll route. Identical to
// "/pending/{id}" but for entries whose downstream hop is the mission-aware
// "/jwt/mission" (each poll re-drives RunChainAsync with the stored path).
app.MapGet("/mission-pending/{id}", async (HttpContext ctx, string id, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null)
    {
        return Results.NotFound(new { error = "unknown_pending", id });
    }

    try
    {
        var result = await RunChainAsync(ctx, entry.UpstreamToken, entry.DownstreamPath);
        pending.Remove(id);
        return result;
    }
    catch (AAuthInteractionChainedException)
    {
        return ReEmitChainedInteraction(ctx, entry);
    }
    catch (AAuthInteractionDeniedException)
    {
        pending.Remove(id);
        ctx.Response.Headers["Cache-Control"] = "no-store";
        return Results.Json(
            new { error = "denied", detail = "the user denied this request" },
            statusCode: StatusCodes.Status403Forbidden);
    }
});

app.Run();

// Marker type for WebApplicationFactory in tests.
namespace Orchestrator { public class Entry; }
