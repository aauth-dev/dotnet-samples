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
using Concierge;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Concierge identity: acts as both a resource AND an agent. Like a travel
// concierge, the user asks it to arrange something and it makes the
// downstream calls on their behalf.
// Generates its own signing key on startup (demo only).
// -----------------------------------------------------------------------
var conciergeKey = AAuthKey.Generate();
const string ConciergeKid = "concierge-1";
const string ConciergeScope = "concierge";
const string DownstreamAgent = "downstream";
var conciergeUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5200";
// The plain call chain hops to the Calendar (three-party). The mission-governed
// chain hops to the mission-aware Trips so a mission in the upstream auth token
// is forwarded and re-bound at each hop. Two downstreams because the Aria suite
// splits these concerns across separate resource servers.
var downstreamUrl = builder.Configuration["AAuth:Downstream"] ?? "http://localhost:5001";
var missionDownstreamUrl = builder.Configuration["AAuth:MissionDownstream"] ?? "http://localhost:5002";
var psUrl = builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100";
var walletUrl = builder.Configuration["AAuth:Wallet"] ?? "http://localhost:5003";
var accessServerUrl = builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5500";
var agentId = builder.Configuration["AAuth:AgentId"] ?? "aauth:concierge@localhost";

builder.Services.AddSingleton(conciergeKey);
builder.Services.AddSingleton<PendingStore>();
// No user to relay to: a downstream interaction is chained back to the caller (§Interaction Chaining).
builder.Services.AddSingleton<IAAuthInteractionHandler, ChainInteractionHandler>();

// The downstream agent: one registration for every inbound request. It self-issues its agent
// token (iss = conciergeUrl, §Call Chaining Identity), chains the verified upstream auth token of
// the current request (ChainFromHttpContext), and routes each exchange to the PS that token names.
// The registered ChainInteractionHandler chains a downstream consent back to the caller, so the
// agent declares no `interaction` capability (§AAuth-Capabilities).
builder.Services.AddAAuthAgent(DownstreamAgent, options =>
{
    options.Signer = conciergeKey;
    options.SelfIssued.Issuer = conciergeUrl;
    options.SelfIssued.Subject = agentId;
    options.SelfIssued.KeyId = ConciergeKid;
    options.PersonServer = psUrl;
    options.ChainFromHttpContext = true;
    options.HandleInteractions = false;
    options.Challenge.Capabilities = [];
    options.EgressPolicy = SampleEgress.Policy;
    options.InnerHandler = new ChainCaptureHandler { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) };
    options.TransportContract = AAuthTransportContract.EnforcesEgressPolicy;
});

// Resource role: verifier, token verifier, discovery clients (pooled handler), JTI store, and the
// published metadata — no manual HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.EgressPolicy = SampleEgress.Policy;
    o.Issuer = conciergeUrl;
    o.SigningKeys[ConciergeKid] = conciergeKey;
    o.Name = "Concierge Demo";
    o.ScopeDescriptions = new Dictionary<string, string>
    {
        [ConciergeScope] = "Arrange calls to downstream resources on the user's behalf",
        ["wallet.read"] = "Ask the concierge to read the travel wallet",
    };
});

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints: resource metadata + agent metadata + JWKS
// -----------------------------------------------------------------------
app.MapAAuthWellKnown();

// Agent metadata: downstream resources discover this to verify our identity.
app.MapAAuthAgentWellKnown(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.Issuer = conciergeUrl;
    options.Name = "Concierge Demo";
    options.SigningKeys = new AAuthSigningKeySet { [ConciergeKid] = conciergeKey };
});

// -----------------------------------------------------------------------
// Self-issued agent identity: per §Call Chaining Identity, the Concierge
// is its own AP — it self-issues agent tokens signed by its own key.
// This ensures agent_token.iss == resource URL, satisfying §Upstream Token
// Verification step 3 (aud in upstream_token matches intermediary resource).
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Verification + Challenge middleware: validates the HTTP signature,
// verifies the JWT issuer, and auto-challenges agent tokens with a
// resource token requiring an auth token for access.
// -----------------------------------------------------------------------
bool IsWalletPath(PathString path) => path == "/wallet" || path.StartsWithSegments("/wallet-pending");

app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known") && !IsWalletPath(ctx.Request.Path),
    branch => branch.UseAAuthIntermediary(
        verification =>
        {
            verification.EgressPolicy = SampleEgress.Policy;
            verification.ResourceIdentifier = conciergeUrl;
            verification.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { psUrl };
        },
        challenge =>
        {
            challenge.EgressPolicy = SampleEgress.Policy;
            challenge.AccessMode = AAuthAccessMode.RequireAuthToken;
            challenge.ResourceSigningKeys = new AAuthSigningKeySet(ConciergeKid, conciergeKey);
            challenge.ResourceIdentifier = conciergeUrl;
            challenge.DefaultScopes = ConciergeScope;
        }));

// -----------------------------------------------------------------------
// GET / — Concierge endpoint (call chaining via WithCallChaining).
//
// The middleware handles verification + 401 challenge automatically.
// Only auth-token callers reach this handler. The downstream client routes
// the exchange to the correct PS/AS using the upstream auth token.
//
// Interaction Chaining (AAuth §Interaction Chaining): the Concierge has no
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
// AAuthInteractionDeniedException when the user denied. <paramref name="downstreamBase"/>
// + <paramref name="downstreamPath"/> select the downstream resource — Calendar
// "/events" for the plain chain or the mission-aware Trips "/trips" for a
// mission-governed chain. WithCallChaining routes every downstream request to the
// PS the upstream token names (its `ps`); a `mission_s256` in the upstream token
// governs every hop (§Call Chaining).
app.UseWhen(ctx => IsWalletPath(ctx.Request.Path), branch => branch.UseAAuthIntermediary(
    verification =>
    {
        verification.EgressPolicy = SampleEgress.Policy;
        verification.ResourceIdentifier = conciergeUrl;
        verification.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { accessServerUrl };
        verification.Trust.PersonServers.Allowed = new HashSet<string> { psUrl };
    },
    challenge =>
    {
        challenge.EgressPolicy = SampleEgress.Policy;
        challenge.ResourceSigningKeys = new AAuthSigningKeySet(ConciergeKid, conciergeKey);
        challenge.ResourceIdentifier = conciergeUrl;
        challenge.AccessServer = accessServerUrl;
        challenge.DefaultScopes = "wallet.read";
        challenge.ScopeDescriptions = new Dictionary<string, string> { ["wallet.read"] = "Read the travel wallet through the concierge" };
    }));

async Task<IResult> RunChainAsync(HttpContext ctx, string downstreamBase, string downstreamPath)
{
    // The registered agent chains this request's upstream auth token (the one the pending
    // routes re-verify, equal to the parked entry's) into its person token and auth token
    // requests (§Call Chaining). A chained consent unwinds as AAuthInteractionChainedException.
    var exchanges = ChainCaptureHandler.Begin();
    var downstream = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient(DownstreamAgent);

    using var response = await downstream.GetAsync($"{downstreamBase.TrimEnd('/')}{downstreamPath}", ctx.RequestAborted);
    response.EnsureSuccessStatusCode();
    var body = await response.Content.ReadAsStringAsync();
    JsonNode? downstreamJson = null;
    try { downstreamJson = JsonNode.Parse(body); } catch { }

    var upstreamResult = ctx.GetAAuthVerification();
    var downstreamName = downstreamPath.StartsWith("/wallet", StringComparison.Ordinal) ? "Wallet"
        : downstreamPath.StartsWith("/trips", StringComparison.Ordinal) ? "Trips" : "Calendar";
    return Results.Ok(new
    {
        chain = $"Agent → Concierge → {downstreamName}",
        upstream = new
        {
            scheme = upstreamResult?.Scheme,
            issuer = upstreamResult?.Issuer,
            ps = upstreamResult?.PersonServer,
            sub = upstreamResult?.Subject,
            mission_s256 = upstreamResult?.MissionS256,
            // Render the token type as its protocol `typ` string (e.g. "aa-auth+jwt")
            // rather than letting System.Text.Json emit the enum's integer value.
            tokenType = upstreamResult?.TokenType.ToHeaderValue(),
        },
        concierge = new
        {
            identity = agentId,
            action = "call-chained to downstream with upstream_token",
        },
        downstream = downstreamJson,
        exchanges,
    });
}

// Re-emit the Concierge's own 202 requirement=interaction for a parked
// chained request: its own Location (the pending URL, keyed by the entry's
// poll-route prefix), the PS's pass-through interaction url/code. Spec
// §Interaction Chaining + §Deferred Responses.
IResult ReEmitChainedInteraction(HttpContext ctx, PendingStore.Entry entry)
{
    ctx.Response.Headers.Location = $"{entry.PendingPrefix}/{entry.Id}";
    ctx.Response.Headers["Retry-After"] = "1";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    ctx.Response.Headers[AAuthRequirementHeader.Name] =
        Interaction.Format(entry.InteractionUrl, entry.InteractionCode, SampleEgress.Policy);
    return Results.Json(new { status = "interaction_required" }, statusCode: StatusCodes.Status202Accepted);
}

app.MapGet("/wallet", async (HttpContext context, PendingStore pending) =>
{
    var upstream = context.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (upstream is null) return AAuthProblemDetails.Create("invalid_request", statusCode: 403);
    try
    {
        return await RunChainAsync(context, walletUrl, "/wallet");
    }
    catch (AAuthInteractionChainedException ex)
    {
        var entry = pending.Add(upstream, ex.Interaction.Url, ex.Interaction.Code,
            downstreamBase: walletUrl, downstreamPath: "/wallet", pendingPrefix: "/wallet-pending");
        return ReEmitChainedInteraction(context, entry);
    }
});

app.MapGet("/", async (HttpContext ctx, PendingStore pending) =>
{
    var upstreamToken = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (string.IsNullOrEmpty(upstreamToken))
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing upstream auth token", statusCode: StatusCodes.Status401Unauthorized);
    }

    try
    {
        return await RunChainAsync(ctx, downstreamUrl, "/events");
    }
    catch (AAuthInteractionChainedException ex)
    {
        // Downstream needs the user's consent. Park it and chain the 202 up.
        var entry = pending.Add(upstreamToken, ex.Interaction.Url, ex.Interaction.Code);
        return ReEmitChainedInteraction(ctx, entry);
    }
});

// GET /mission — the mission-governed twin of "/". Identical chaining, but the
// downstream hop targets the mission-aware Trips "/trips" so a mission present
// in the upstream auth token is forwarded and re-bound at each hop (§Mission
// Context at Resources, §Call Chaining).
app.MapGet("/mission", async (HttpContext ctx, PendingStore pending) =>
{
    var upstreamToken = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (string.IsNullOrEmpty(upstreamToken))
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing upstream auth token", statusCode: StatusCodes.Status401Unauthorized);
    }

    try
    {
        return await RunChainAsync(ctx, missionDownstreamUrl, "/trips");
    }
    catch (AAuthInteractionChainedException ex)
    {
        var entry = pending.Add(
            upstreamToken, ex.Interaction.Url, ex.Interaction.Code,
            downstreamBase: missionDownstreamUrl, downstreamPath: "/trips", pendingPrefix: "/mission-pending");
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
app.MapMethods("/pending/{id}", ["GET", "DELETE"], HandlePendingAsync);

// GET /mission-pending/{id} — the mission chain's poll route. Identical to
// "/pending/{id}" but for entries whose downstream hop is the mission-aware
// Trips "/trips" (each poll re-drives RunChainAsync with the stored path).
app.MapMethods("/mission-pending/{id}", ["GET", "DELETE"], HandlePendingAsync);

// GET /wallet-pending/{id} — the four-party /wallet chain's poll route, verified
// by the /wallet branch (AS-issued upstream auth tokens).
app.MapMethods("/wallet-pending/{id}", ["GET", "DELETE"], HandlePendingAsync);

async Task<IResult> HandlePendingAsync(HttpContext ctx, string id, PendingStore pending)
{
    var entry = pending.Get(id);
    if (entry is null || ctx.Request.Path != $"{entry.PendingPrefix}/{entry.Id}"
        || !entry.Matches(ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token))
    {
        return AAuth.Server.AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound,
            extensions: new Dictionary<string, object?> { ["id"] = id });
    }

    return await entry.Lifecycle.ExecuteAsync(ctx, entry.ExpiresAt, TimeProvider.System, async () =>
    {
        if (HttpMethods.IsDelete(ctx.Request.Method))
        {
            entry.Lifecycle.Cancel();
            return Results.NoContent();
        }
        // entry.Matches(...) above proved this request re-presents the parked upstream token.
        try { return await RunChainAsync(ctx, entry.DownstreamBase, entry.DownstreamPath); }
        catch (AAuthInteractionChainedException) { return ReEmitChainedInteraction(ctx, entry); }
        catch (AAuthInteractionDeniedException)
        {
            return AAuthProblemDetails.Create("denied", "the user denied this request", statusCode: StatusCodes.Status403Forbidden);
        }
    });
}

app.Run();

// Marker type for WebApplicationFactory in tests.
namespace Concierge
{
    public class Entry;

    internal sealed class ChainInteractionHandler : IAAuthInteractionHandler
    {
        public Task OnInteractionRequiredAsync(AAuth.Headers.Interaction interaction, CancellationToken cancellationToken)
            => throw new AAuthInteractionChainedException(interaction);
    }
}
