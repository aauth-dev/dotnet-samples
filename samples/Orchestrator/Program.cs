using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;

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
var apUrl = builder.Configuration["AAuth:AgentProvider"] ?? "http://localhost:5301";
var psUrl = builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100";
var agentId = builder.Configuration["AAuth:AgentId"] ?? "aauth:orchestrator@ap.example";

builder.Services.AddSingleton(orchestratorKey);
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(new TokenVerifier());
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
app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new JsonObject
{
    ["issuer"] = orchestratorUrl,
    ["jwks_uri"] = $"{orchestratorUrl.TrimEnd('/')}/.well-known/jwks.json",
}));

// -----------------------------------------------------------------------
// Enrollment state (lazy — enrols with the AP on first request).
// -----------------------------------------------------------------------
IAAuthKey? enrolledKey = null;
string? enrolledKeyId = null;
IKeyStore? keyStore = null;
string? refreshEndpoint = null;
var enrollLock = new SemaphoreSlim(1, 1);

async Task EnsureEnrolledAsync()
{
    if (enrolledKey is not null) return;
    await enrollLock.WaitAsync();
    try
    {
        if (enrolledKey is not null) return;

        keyStore = KeyStore.Default();
        var metadataClient = new MetadataClient(new HttpClient());
        var metaUrl = MetadataClient.BuildUrl(apUrl, "aauth-agent.json");
        var apMeta = await metadataClient.FetchAsync(metaUrl);
        var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apUrl}/enrol";
        refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apUrl}/refresh";

        var apClient = new AgentProviderClient(new HttpClient(), keyStore);
        var result = await apClient.EnrolAsync(apUrl, agentId, enrolEndpoint, psUrl);
        enrolledKey = result.Key;
        enrolledKeyId = result.KeyId;
    }
    finally
    {
        enrollLock.Release();
    }
}

// -----------------------------------------------------------------------
// Verification middleware: validates the HTTP signature and verifies the
// JWT issuer (both agent tokens and auth tokens) via JWKS discovery.
// The ResourceIdentifier ensures auth token `aud` is checked against us.
// -----------------------------------------------------------------------
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        ResourceIdentifier = orchestratorUrl,
        RequireIssuerVerification = true,
    }));

// -----------------------------------------------------------------------
// GET / — Orchestrator endpoint.
//
// Demonstrates spec-compliant call chaining (§Multi-Hop Resource Access):
//   1. Verify the incoming signed request (middleware did this).
//   2. Extract the upstream auth token from the caller's Signature-Key.
//   3. Call the downstream resource (WhoAmI) — get a 401 challenge.
//   4. Exchange the resource token at the PS WITH the upstream_token
//      so the PS builds the nested act chain.
//   5. Retry with the chained auth token.
//   6. Return the downstream response (which now shows the full chain).
// -----------------------------------------------------------------------
app.MapGet("/", async (HttpContext ctx) =>
{
    // Step 1: Get info about the incoming caller from middleware.
    // The middleware already verified the HTTP signature AND the JWT issuer
    // (agent or auth token) via JWKS discovery.
    var upstreamResult = ctx.Features.Get<AAuthVerificationResult>();
    var parsedInfo = (SignatureKeyParser.ParsedSignatureKeyInfo)
        ctx.Items[AAuthVerificationMiddleware.ParsedInfoItemKey]!;

    var typ = (string?)parsedInfo.Header?["typ"];

    // ── Reject non-JWT callers (HWK/JWKS-URI) ───────────────────────
    // The Orchestrator only supports three-party JWT flows for call chaining.
    if (typ is null)
    {
        return Results.Json(
            new { error = "unsupported_scheme", detail = "Orchestrator requires sig=jwt (agent or auth token)." },
            statusCode: StatusCodes.Status400BadRequest);
    }

    // ── Agent token: challenge the caller with a resource token ──────
    // The Orchestrator is itself a resource — callers must present an auth
    // token (obtained from a PS) before we forward calls downstream.
    if (typ == AgentTokenBuilder.TokenType)
    {
        // Middleware already verified the agent token's signature via JWKS.
        // Extract the PS URL and agent identity from the verified payload.
        var callerAgent = (string?)parsedInfo.Payload?["sub"] ?? "unknown";
        var callerPs = (string?)parsedInfo.Payload?["ps"];
        if (string.IsNullOrEmpty(callerPs))
        {
            return Results.Json(new { error = "no_person_server", detail = "Agent token must contain 'ps' claim for three-party flow." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        // Build and return a resource token for this Orchestrator.
        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = orchestratorUrl,
            Audience = callerPs,
            Agent = callerAgent,
            AgentJkt = parsedInfo.ConfirmationKey!.ComputeJwkThumbprint(),
            Key = orchestratorKey,
            KeyId = OrchestratorKid,
            Scope = OrchestratorScope,
        }.Build();

        ctx.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthRequirementHeader.FormatAuthToken(resourceToken);
        return Results.Json(new { error = "auth_token_required" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // ── Auth token: proceed with downstream call chaining ────────────
    // The middleware verified: JWT signature, aud=orchestratorUrl, cnf.jwk
    // binding, and act.sub. The caller's auth token becomes our upstream_token.
    var upstreamAuthToken = parsedInfo.Jwt!;

    // Step 2: Ensure we have our own agent identity.
    await EnsureEnrolledAsync();

    // Step 3: Grant consent at the PS for the Orchestrator to call WhoAmI.
    using var adminHttp = new HttpClient();
    try
    {
        await adminHttp.PostAsJsonAsync(
            $"{psUrl.TrimEnd('/')}/admin/consent",
            new { agent = agentId, resource = downstreamUrl.TrimEnd('/') });
    }
    catch
    {
        // /admin/consent only exists on MockPersonServer — swallow
    }

    // Step 4: Build the Orchestrator's own signed client (agent token mode).
    // This client does NOT have WithChallengeHandling — we handle the
    // challenge manually so we can pass upstream_token.
    using var client = new AAuthClientBuilder(enrolledKey!)
        .WithTokenRefresh(async (_, ct) =>
        {
            var apClient = new AgentProviderClient(new HttpClient(), keyStore!);
            return await apClient.RefreshAsync(refreshEndpoint!, enrolledKeyId!, ct);
        })
        .Build();

    // Step 5: First call to downstream — expect a 401 challenge.
    var firstResponse = await client.GetAsync(downstreamUrl);

    JsonNode? downstreamJson = null;

    if (firstResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized
        && firstResponse.Headers.Contains(AAuthRequirementHeader.Name))
    {
        // Parse the resource token from the challenge.
        var requirementRaw = firstResponse.Headers.GetValues(AAuthRequirementHeader.Name).First();
        var requirement = AAuthRequirementHeader.Parse(requirementRaw);

        // Step 6: Exchange at PS WITH upstream_token (call-chaining).
        // This causes the PS to build a nested act claim.
        var metadata = app.Services.GetRequiredService<MetadataClient>();
        var exchangeClient = new TokenExchangeClient(client, metadata);
        var chainedAuthToken = await exchangeClient.ExchangeAsync(
            psUrl,
            requirement.ResourceToken!,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamToken: upstreamAuthToken);

        // Step 7: Retry with the chained auth token.
        using var chainedClient = new AAuthClientBuilder(enrolledKey!)
            .UseJwt(chainedAuthToken)
            .Build();

        var retryResponse = await chainedClient.GetAsync(downstreamUrl);
        var retryBody = await retryResponse.Content.ReadAsStringAsync();
        try { downstreamJson = JsonNode.Parse(retryBody); } catch { }
    }
    else
    {
        // No challenge — resource accepted directly (shouldn't happen in
        // normal flow, but handle gracefully).
        var body = await firstResponse.Content.ReadAsStringAsync();
        try { downstreamJson = JsonNode.Parse(body); } catch { }
    }

    // Step 8: Return combined result showing the full chain.
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
});

app.Run();

// Marker type for WebApplicationFactory in tests.
namespace Orchestrator { public class Entry; }
