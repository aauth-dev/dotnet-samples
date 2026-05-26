using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
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
        },
        new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = orchestratorKey,
            ResourceKeyId = OrchestratorKid,
            ResourceIdentifier = orchestratorUrl,
            DefaultScopes = OrchestratorScope,
        }));

// -----------------------------------------------------------------------
// GET / — Orchestrator endpoint (call chaining via WithCallChaining).
//
// The middleware handles verification + 401 challenge automatically.
// Only auth-token callers reach this handler. WithCallChaining(ctx) reads
// the upstream auth token from UpstreamAuthTokenFeature and routes the
// downstream exchange to the correct PS/AS automatically.
// -----------------------------------------------------------------------
app.MapGet("/", async (HttpContext ctx) =>
{
    await EnsureEnrolledAsync();

    // Grant consent at the PS (demo convenience — real deployments pre-grant).
    using var adminHttp = new HttpClient();
    try
    {
        await adminHttp.PostAsJsonAsync(
            $"{psUrl.TrimEnd('/')}/admin/consent",
            new { agent = agentId, resource = downstreamUrl.TrimEnd('/') });
    }
    catch { /* /admin/consent only exists on MockPersonServer */ }

    // Build a call-chaining client: upstream token routing + auto-challenge.
    using var downstream = new AAuthClientBuilder(enrolledKey!)
        .WithTokenRefresh(async (_, ct) =>
        {
            var apClient = new AgentProviderClient(new HttpClient(), keyStore!);
            return await apClient.RefreshAsync(refreshEndpoint!, enrolledKeyId!, ct);
        })
        .WithCallChaining(ctx)
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    var body = await response.Content.ReadAsStringAsync();
    JsonNode? downstreamJson = null;
    try { downstreamJson = JsonNode.Parse(body); } catch { }

    var upstreamResult = ctx.Features.Get<AAuthVerificationResult>();
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

// -----------------------------------------------------------------------
// Interaction Chaining Example (commented out)
//
// If the downstream PS requires user consent, use onInteractionRequired
// to propagate the 202 back to the caller. See docs/advanced/interaction-chaining.md.
//
// app.MapGet("/with-interaction", async (HttpContext ctx) =>
// {
//     await EnsureEnrolledAsync();
//
//     using var downstream = new AAuthClientBuilder(enrolledKey!)
//         .WithTokenRefresh(async (_, ct) =>
//         {
//             var apClient = new AgentProviderClient(new HttpClient(), keyStore!);
//             return await apClient.RefreshAsync(refreshEndpoint!, enrolledKeyId!, ct);
//         })
//         .WithCallChaining(ctx)
//         .WithChallengeHandling(opts =>
//         {
//             opts.OnInteractionRequired = async (interaction, ct) =>
//             {
//                 // Propagate interaction requirement to caller
//                 ctx.Response.StatusCode = 202;
//                 ctx.Response.Headers["Location"] = "/pending/123";
//                 ctx.Response.Headers["AAuth-Requirement"] =
//                     $"requirement=interaction; url=\"{interaction.Url}\"; code=\"{interaction.Code}\"";
//                 await ctx.Response.StartAsync(ct);
//             };
//         })
//         .Build();
//
//     var response = await downstream.GetAsync(downstreamUrl);
//     return Results.Ok(await response.Content.ReadAsStringAsync());
// });
// -----------------------------------------------------------------------

app.Run();

// Marker type for WebApplicationFactory in tests.
namespace Orchestrator { public class Entry; }
