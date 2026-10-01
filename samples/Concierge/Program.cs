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
// Every chained call attaches its AAuthChainedOperation's handler per request; this fallback aborts
// any other downstream request that would otherwise wait on a user the Concierge doesn't have.
builder.Services.AddSingleton<IAAuthInteractionHandler, ChainInteractionHandler>();

// The downstream agent: one registration for every inbound request. It self-issues its agent
// token (iss = conciergeUrl, §Call Chaining Identity), chains the caller's upstream auth token
// (set per request with AAuthRequestOptions.UpstreamToken; ChainFromHttpContext is the fallback),
// and routes each exchange to the PS that token names. A downstream consent is chained back to
// the caller rather than shown to a user here, so the agent declares no `interaction`
// capability (§AAuth-Capabilities).
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
bool IsPublicInteractionPath(PathString path) => path.StartsWithSegments("/chain-interaction");

app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !IsWalletPath(ctx.Request.Path)
        && !IsPublicInteractionPath(ctx.Request.Path),
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
// user of its own, so it CANNOT relay a downstream consent prompt. It runs the
// downstream call as an AAuthChainedOperation: when the downstream PS (or AS)
// answers 202 + requirement=interaction, the operation records the interaction
// and the SDK keeps polling the downstream pending URL with GET (§Polling with
// GET) in the background. The handler parks a pending entry and returns its OWN
// 202 + requirement=interaction to the caller. The user first visits a
// Concierge interaction URL, which redirects to the downstream PS interaction.
// When the downstream auth token arrives, the operation completes the call and
// the caller's next poll gets the result. The downstream request is never re-sent.
// -----------------------------------------------------------------------

// Run the downstream chained call for one inbound request. It may outlive that
// request (it keeps polling a downstream consent), so it uses only what was
// captured up front: the upstream auth token travels per request
// (AAuthRequestOptions.UpstreamToken), and the interaction handler is the
// operation's. <paramref name="downstreamBase"/> + <paramref name="downstreamPath"/>
// select the downstream resource — Calendar "/events" for the plain chain or the
// mission-aware Trips "/trips" for a mission-governed chain. The SDK routes every
// downstream request to the PS the upstream token names (its `ps`); a
// `mission_s256` in the upstream token governs every hop (§Call Chaining).
app.UseWhen(ctx => IsWalletPath(ctx.Request.Path), branch => branch.UseAAuthIntermediary(
    verification =>
    {
        verification.EgressPolicy = SampleEgress.Policy;
        verification.ResourceIdentifier = conciergeUrl;
        // Four-party branch: the Wallet's Access Server issues the auth token
        // (§PS-AS Federation), so require dwk=aauth-access.json from that AS only.
        verification.ExpectedAuthTokenDwk = AAuthConstants.DwkFiles.Access;
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

async Task<IResult> RunChainAsync(string upstreamToken, AAuthVerificationResult? upstreamResult,
    IAAuthInteractionHandler interactions, string downstreamBase, string downstreamPath, CancellationToken cancellationToken)
{
    var exchanges = ChainCaptureHandler.Begin();
    var downstream = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient(DownstreamAgent);

    using var request = new HttpRequestMessage(HttpMethod.Get, $"{downstreamBase.TrimEnd('/')}{downstreamPath}");
    request.Options.Set(AAuthRequestOptions.UpstreamToken, upstreamToken);
    request.Options.Set(AAuthRequestOptions.InteractionHandler, interactions);
    using var response = await downstream.SendAsync(request, cancellationToken);
    response.EnsureSuccessStatusCode();
    var body = await response.Content.ReadAsStringAsync(cancellationToken);
    JsonNode? downstreamJson = null;
    try { downstreamJson = JsonNode.Parse(body); } catch { }

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
// chained request: its own Location, interaction URL and interaction code
// (re-keyed when the downstream moved to a new interaction).
IResult ReEmitChainedInteraction(HttpContext ctx, PendingStore.Entry entry)
    => AAuthChainedInteractions.Accepted(ctx, entry.Interaction, SampleEgress.Policy);

// The finished operation's outcome: its result, or the §Polling Error Codes
// response for a downstream denial, expiry or revocation.
async Task<IResult> CompletedChainAsync(AAuthChainedOperation<IResult> operation)
{
    try { return await operation.Completion; }
    catch (Exception ex) when (AAuthChainedInteractions.PollingFailure(ex) is { } failure) { return failure; }
}

// Start the downstream chain for an inbound request. If it finishes without
// downstream interaction, answer with its result; otherwise park it under a
// Concierge-owned code and pending URL and answer with the Concierge's own 202.
async Task<IResult> StartChainAsync(HttpContext ctx, PendingStore pending, string pendingPrefix,
    string downstreamBase, string downstreamPath)
{
    var upstreamToken = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (string.IsNullOrEmpty(upstreamToken))
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "missing upstream auth token", statusCode: StatusCodes.Status401Unauthorized);
    }

    var upstreamResult = ctx.GetAAuthVerification();
    var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
        JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(upstreamToken.Split('.')[1]))!["exp"]!.GetValue<long>());
    var operation = await AAuthChainedOperation<IResult>.StartAsync(
        (interactions, ct) => RunChainAsync(upstreamToken, upstreamResult, interactions, downstreamBase, downstreamPath, ct),
        expiresAt, app.Lifetime.ApplicationStopping);
    if (operation.Completion.IsCompleted)
    {
        return await CompletedChainAsync(operation);
    }

    // Read the interaction once: the operation may publish a newer one while we park.
    var snapshot = operation.Interaction!;
    var chained = AAuthChainedInteractions.Park(conciergeUrl, pendingPrefix, "/chain-interaction",
        snapshot.Downstream,
        "concierge.downstream",
        new JsonObject
        {
            ["downstream_base"] = downstreamBase,
            ["downstream_path"] = downstreamPath,
        },
        expiresAt);
    var entry = pending.Add(upstreamToken, chained, pendingPrefix, operation, snapshot.Version);
    return ReEmitChainedInteraction(ctx, entry);
}

app.MapGet("/wallet", (HttpContext context, PendingStore pending) =>
    StartChainAsync(context, pending, "/wallet-pending", walletUrl, "/wallet"));

app.MapGet("/", (HttpContext ctx, PendingStore pending) =>
    StartChainAsync(ctx, pending, "/pending", downstreamUrl, "/events"));

// GET /mission — the mission-governed twin of "/". Identical chaining, but the
// downstream hop targets the mission-aware Trips "/trips" so a mission present
// in the upstream auth token is forwarded and re-bound at each hop (§Mission
// Context at Resources, §Call Chaining).
app.MapGet("/mission", (HttpContext ctx, PendingStore pending) =>
    StartChainAsync(ctx, pending, "/mission-pending", missionDownstreamUrl, "/trips"));

app.MapGet("/chain-interaction/{id}", (string id, string? code, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null || !entry.MatchesCode(code))
        return AAuth.Server.AAuthProblemDetails.Polling(AAuth.Errors.PollingErrorCode.InvalidCode,
            extensions: new Dictionary<string, object?> { ["id"] = id });
    // Any code this entry issued leads to the latest downstream interaction.
    return AAuthChainedInteractions.RedirectToDownstream(entry.Interaction);
});

// -----------------------------------------------------------------------
// GET /pending/{id} — the caller polls here while its user approves the
// downstream consent at the PS interaction page. Signed + auth-token gated by
// the same middleware as "/". Each poll reads the background operation, which
// is polling the downstream pending URL itself; nothing is re-sent downstream.
// Returns:
//   * 202 + requirement=interaction while the downstream is still pending
//     (a new code when the downstream moved to a new interaction)
//   * 200 + combined chain result once the downstream auth token resolves
//   * 403 denied / abandoned / revoked, or 408 expired, from the downstream outcome
//   * 410 invalid_code if the pending id is unknown, mismatched or already consumed
// DELETE cancels the background operation.
// -----------------------------------------------------------------------
app.MapMethods("/pending/{id}", ["GET", "DELETE"], HandlePendingAsync);

// GET /mission-pending/{id} — the mission chain's poll route. Identical to
// "/pending/{id}" but for entries whose downstream hop is the mission-aware
// Trips "/trips".
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
        return AAuth.Server.AAuthProblemDetails.Polling(AAuth.Errors.PollingErrorCode.InvalidCode,
            extensions: new Dictionary<string, object?> { ["id"] = id });
    }

    return await entry.Lifecycle.ExecuteAsync(ctx, entry.ExpiresAt, TimeProvider.System, async () =>
    {
        if (HttpMethods.IsDelete(ctx.Request.Method))
        {
            entry.Operation?.Cancel();
            entry.Lifecycle.Cancel();
            return Results.NoContent();
        }
        // entry.Matches(...) above proved this request re-presents the parked upstream token.
        if (entry.Operation is { Completion.IsCompleted: true } operation)
        {
            return await CompletedChainAsync(operation);
        }
        return ReEmitChainedInteraction(ctx, entry);
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
