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
// Well-known endpoints: resource metadata + agent metadata + JWKS.
//
// Spec §Call Chaining Identity: a resource that acts as an agent MUST
// publish agent metadata so downstream parties can verify its identity.
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

        // Demo-only convenience: grant consent at the MockPersonServer so
        // the chained exchange succeeds without manual setup. Real PSes
        // require user interaction; this admin shortcut only exists in
        // the mock server bundled with the samples.
        try
        {
            using var adminHttp = new HttpClient();
            await adminHttp.PostAsJsonAsync(
                $"{psUrl.TrimEnd('/')}/admin/consent",
                new { agent = agentId, resource = downstreamUrl.TrimEnd('/') });
        }
        catch { /* /admin/consent only exists on MockPersonServer */ }
    }
    finally
    {
        enrollLock.Release();
    }
}

// -----------------------------------------------------------------------
// Intermediary middleware: verification + auto-challenge.
//
// Spec compliance:
//   • UseAAuthVerification — HTTP signature PoP + JWT issuer verification
//     against JWKS (§Auth Token Verification, §Agent Token Verification).
//   • UseAAuthChallenge — when the caller presents an agent token, mints
//     an aa-resource+jwt and returns 401 with the AAuth-Requirement
//     header (§Resource Token Issuance).
//   • When the caller presents an aa-auth+jwt, the middleware sets an
//     UpstreamAuthTokenFeature so the endpoint can hand it to the
//     call-chaining client without re-parsing Signature-Key.
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
// GET / — Orchestrator endpoint.
//
// Demonstrates spec-compliant call chaining (§Call Chaining) using the
// simplified SDK surface. The middleware guarantees we only reach here
// with a verified aa-auth+jwt. The downstream client is configured with
// WithCallChaining(ctx); the SDK automatically:
//
//   1. Signs the first downstream call with our own agent token.
//   2. On 401 challenge, exchanges at the routed PS/AS (resolved per
//      §Call Chaining: mission.approver else iss).
//   3. Passes the caller's auth token as upstream_token so the PS can
//      build the nested act claim (§Upstream Token Verification).
//   4. Retries with the chained auth token.
// -----------------------------------------------------------------------
app.MapGet("/", async (HttpContext ctx) =>
{
    var upstreamResult = ctx.Features.Get<AAuthVerificationResult>();

    await EnsureEnrolledAsync();

    using var downstream = new AAuthClientBuilder(enrolledKey!)
        .WithTokenRefresh(async (_, ct) =>
        {
            var apClient = new AgentProviderClient(new HttpClient(), keyStore!);
            return await apClient.RefreshAsync(refreshEndpoint!, enrolledKeyId!, ct);
        })
        .WithChallengeHandling()
        .WithCallChaining(ctx)
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    var body = await response.Content.ReadAsStringAsync();
    JsonNode? downstreamJson = null;
    try { downstreamJson = JsonNode.Parse(body); } catch { }

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
