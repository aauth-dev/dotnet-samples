using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// =============================================================================
// MissionAgent — a console showcase of the AAuth *mission* model and the
// Person Server acting as the policy-enforcement point (§Missions).
//
// A mission is a durable, human-approved statement of intent. Once approved,
// the PS governs every downstream token and permission request *under* that
// mission with a three-gate model (§Agent Token Request):
//
//   gate 1  terminated mission        -> rejected outright
//   gate 2a in-scope (resource,scope) -> granted silently
//   gate 2b prior consent this run    -> granted silently
//   gate 3  out of scope              -> the user is prompted to decide
//
// This sample drives the full lifecycle against the live mock servers:
//   MockAgentProvider (:5301) -> MockPersonServer (:5100) -> Trips (:5002)
//
// Run the three servers first (see samples/MissionAgent/README.md), then:
//   dotnet run --project samples/MissionAgent
//
// By default every out-of-scope prompt is *interactive*: the agent prints the
// Person Server's consent URL and waits while you approve or deny in your
// browser. Pass --auto to resolve prompts via the PS's scripted defaults
// (useful for unattended smoke runs).
// =============================================================================

const string Usage =
    "Usage: MissionAgent [--ap <url>] [--ps <url>] [--resource <url>] [--sub <agent-id>]\n"
    + "                   [--mission-approved <scope>]... [--auto]";

// The scope the Trips `/trips` resource demands (and therefore the scope the
// PS gates the token request on). It is mission-approved by default, so steps
// 3-4 resolve silently (gate 2a - InScope).
const string ResourceScope = "trips.read";

// The elevated scope the Trips `/trips/book` resource demands. It is
// deliberately NOT part of the mission's intent, so requesting it prompts the
// user (step 5) unless declared mission-approved as in-scope.
const string ElevatedScope = "trips.book";

string apUrl = "http://localhost:5301";
string personServer = "http://localhost:5100";
string resourceUrl = "http://localhost:5002/trips";
string subject = "aauth:mission-demo@ap.example";
bool interactive = true;
var dashboardOpened = false;
// Scopes declared as within the mission's intent up front (§Agent Token Request,
// gate 2a). A seeded (resource, scope) pair lets that resource access resolve
// *silently* (reason = InScope) instead of prompting. By default the mission
// approves `trips.read`, mirroring the SampleApp mission demo: the Trips token gate
// (steps 3-4) is silent while the elevated scope and the cancel_booking tool still
// prompt. Pass --mission-approved to replace this default set.
var missionApprovedScopes = new List<string> { ResourceScope };
bool missionApprovedOverridden = false;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--help" or "-h":
            Console.WriteLine(Usage);
            return 0;
        case "--auto":
            interactive = false;
            break;
        case "--ap" or "--ps" or "--resource" or "--sub" or "--mission-approved":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"Missing value for {args[i]}.");
                return 1;
            }
            var value = args[++i];
            switch (args[i - 1])
            {
                case "--ap": apUrl = value; break;
                case "--ps": personServer = value; break;
                case "--resource": resourceUrl = value; break;
                case "--sub": subject = value; break;
                case "--mission-approved":
                    // The first --mission-approved flag replaces the default
                    // {trips.read} set so callers get full control of the in-scope list.
                    if (!missionApprovedOverridden)
                    {
                        missionApprovedScopes.Clear();
                        missionApprovedOverridden = true;
                    }
                    missionApprovedScopes.Add(value);
                    break;
            }
            break;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}");
            Console.Error.WriteLine(Usage);
            return 1;
    }
}

apUrl = apUrl.TrimEnd('/');
personServer = personServer.TrimEnd('/');

// The PS gates the token request on the resource token's (iss, scope). The
// resource's iss is the Trips *origin* (not the /trips path), so seed
// the in-scope set against the origin to match what the PS will compare.
var resourceOrigin = new Uri(resourceUrl).GetLeftPart(UriPartial.Authority);
bool resourceScopeMissionApproved = missionApprovedScopes.Contains(ResourceScope, StringComparer.Ordinal);
bool elevatedScopeMissionApproved = missionApprovedScopes.Contains(ElevatedScope, StringComparer.Ordinal);

Section("1. Enrol with the Agent Provider");
// The agent's signing key is long-lived (it spans the agent install). The
// keystore holds the private key; we keep only its handle in memory here.
IKeyStore keyStore = FileKeyStore.Default();
using var apHttp = new SampleHttpClient();
using var discovery = new MetadataClient(apHttp);
var apMeta = await discovery.FetchAsync(MetadataClient.BuildUrl(apUrl, "aauth-agent.json", SampleEgress.Policy));
var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apUrl}/enrol";
var refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apUrl}/refresh";

var apClient = new AgentProviderClient(apHttp, keyStore);
var durableKey = FileKeyStore.Default().LoadOrCreate("mission-agent");
var enrolment = await apClient.EnrolWithKeyAsync(apUrl, null, enrolEndpoint, durableKey, personServer);
subject = enrolment.AgentId ?? throw new InvalidOperationException("AP did not return its assigned identity.");
AAuthKey key = enrolment.Key;
string localKeyHandle = enrolment.LocalKeyHandle;
Console.WriteLine($"   agent id        : {subject}");
Console.WriteLine($"   key thumbprint  : {key.ComputeJwkThumbprint()}");
Console.WriteLine($"   person server   : {personServer}");

// Register the enrolled agent in a generic host. The SDK refreshes its agent token at the
// AP with the durable key (KeyHandle), handles every resource challenge, and exposes typed
// Person Server clients signed as the agent. Governance calls share the challenge settings:
// PromptUserAsync relays each consent, with a generous budget so a human has time to click.
var hostBuilder = Host.CreateApplicationBuilder();
hostBuilder.Logging.ClearProviders();
hostBuilder.Services.AddSingleton(keyStore);
hostBuilder.Services.AddAAuthAgent("mission-agent", options =>
{
    options.KeyHandle = localKeyHandle;
    options.AgentProvider.RefreshEndpoint = refreshEndpoint;
    options.PersonServer = personServer;
    options.EgressPolicy = SampleEgress.Policy;
    options.Challenge.OnInteractionRequired = PromptUserAsync;
    options.Challenge.PollingTimeout = TimeSpan.FromMinutes(5);
});
using var host = hostBuilder.Build();
var agent = host.Services.GetRequiredService<IAAuthAgentFactory>().Get("mission-agent");
var tokenCache = host.Services.GetRequiredKeyedService<IAAuthTokenCache>("mission-agent");
var governance = agent.Governance;

// Tell the mock PS how to resolve prompts. Interactive mode holds each prompt
// open until you decide in the browser; --auto resolves via scripted defaults.
// The mission-approved scopes are seeded as in-scope (resource origin, scope)
// pairs so the matching token request resolves silently at gate 2a (§Agent Token
// Request). By default this includes `trips.read`, so steps 3-4 never prompt.
var inScopeSeed = new JsonArray();
foreach (var scope in missionApprovedScopes)
{
    inScopeSeed.Add(new JsonObject { ["resource"] = resourceOrigin, ["scope"] = scope });
}
await ScriptAsync(new JsonObject
{
    ["reset"] = true,
    ["interactive"] = interactive,
    ["approveMission"] = true,
    ["approveToken"] = true,
    ["approvePermission"] = true,
    ["inScope"] = inScopeSeed,
});
Console.WriteLine($"   prompt mode     : {(interactive ? "interactive (decide in your browser)" : "auto (scripted approvals)")}");
if (missionApprovedScopes.Count > 0)
{
    Console.WriteLine($"   mission-approved: {string.Join(", ", missionApprovedScopes.Select(s => $"{resourceOrigin} / {s}"))} (in scope — no prompt)");
}

Section("2. Propose a mission");
// The user approves a durable statement of intent plus the tools the agent may
// use. The PS returns the mission blob plus its s256 digest, which
// the agent quotes on every later request to bind it to this mission. In
// interactive mode the PS shows a browser consent screen here; in --auto mode it
// resolves the approval itself.
var addToCalendarTool = new MissionTool("add_to_calendar", "Add an itinerary item to the calendar");
var session = await governance.ProposeMissionAsync(new MissionProposal(
    "Plan my weekend trip to Seattle.")
{
    Tools = new[]
    {
        addToCalendarTool,
        new MissionTool("compare_options", "Compare flight and hotel options"),
    },
});
// The session wraps the approved mission and auto-threads its mission_s256
// and the bound PS into every later governed call.
var mission = session.Mission;
Console.WriteLine($"   description     : {mission.Description}");
Console.WriteLine($"   approved by     : {mission.PersonServer}");
Console.WriteLine($"   approved tools  : {string.Join(", ", mission.ApprovedTools.Select(t => t.Name))}");
// The s256 is the SHA-256 of the approval blob's exact bytes, NOT the text:
// tokens carry only mission_s256 as a compact, verifiable reference to the
// mission above (#mission-approval). The description and tools stay with the
// PS, so a leaked token never exposes the mission's prose.
Console.WriteLine($"   mission s256    : {mission.S256}  (thumbprint reference to the description above)");

Section(resourceScopeMissionApproved
    ? "3. Access a mission-aware resource — IN SCOPE (silent, no prompt)"
    : "3. Access a mission-aware resource — first call is OUT OF SCOPE");
// The Trips /trips endpoint is mission-aware: the agent's person token names
// the mission as mission_s256, and the resource token it issues copies it.
// The PS reads that claim and governs the token request. When this (resource,
// scope) is mission-approved as in-scope it resolves silently at gate 2a;
// otherwise it falls outside the mission's approved scope and the PS prompts.
if (resourceScopeMissionApproved)
{
    Console.WriteLine($"   mission-approved: {resourceOrigin} / {ResourceScope} is in-scope, so this is granted silently (gate 2a — InScope)");
}
var first = await AccessMissionResourceAsync(resourceUrl);
Console.WriteLine($"   resource said   : access={first?["access"]}, scope={first?["scope"]}");
// The resource echoes only the mission_s256 reference from the token — the
// same s256 printed in step 2, which maps back to "{mission.Description}".
Console.WriteLine($"   echoed mission  : {first?["mission_s256"]}");
Console.WriteLine($"                     (s256 references: \"{mission.Description}\")");

Section(resourceScopeMissionApproved
    ? "4. Access it again — still silent (IN SCOPE)"
    : "4. Access it again — now silent via PRIOR CONSENT");
// Either the (resource, scope) is in the mission's in-scope set (gate 2a) or it
// was just approved under this mission (gate 2b prior consent); either way the
// PS grants the token silently this time — no prompt.
var second = await AccessMissionResourceAsync(resourceUrl);
Console.WriteLine($"   resource said   : access={second?["access"]}, scope={second?["scope"]} (granted silently)");

Section(elevatedScopeMissionApproved
    ? "5. Access an ELEVATED scope — IN SCOPE (silent, no prompt)"
    : "5. Access an ELEVATED scope — OUT OF MISSION (prompt)");
// The elevated endpoint demands `trips.book`, a scope the mission
// never declared and whose intent ("plan my weekend trip") does not
// cover it. The PS cannot grant it silently: out-of-mission scopes are NOT
// auto-denied — the PS prompts the user (§Agent Token Request gate 3, §Scopes).
// Approve in the browser and the consent accrues to the mission; deny and the
// exchange throws AAuthInteractionDeniedException (denied). Declaring
// trips.book mission-approved (--mission-approved) makes this silent.
if (elevatedScopeMissionApproved)
{
    Console.WriteLine($"   mission-approved: {resourceOrigin} / {ElevatedScope} is in-scope, so this is granted silently (gate 2a — InScope)");
}
var elevatedUrl = $"{resourceOrigin}/trips/book";
try
{
    var elevated = await AccessMissionResourceAsync(elevatedUrl);
    Console.WriteLine($"   resource said   : access={elevated?["access"]}, scope={elevated?["scope"]} (granted after your approval)");
}
catch (AAuthInteractionDeniedException)
{
    Console.WriteLine("   elevated scope  : denied by the user (denied) — the gate-2 token is unaffected");
}

Section("6. Request a permission for a pre-approved tool — silent");
// `add_to_calendar` is an approved tool, so the SDK short-circuits to granted
// without ever calling the PS (§Permission Endpoint). We still hold the
// addToCalendarTool reference from the proposal, so we ask via tool.ToAction()
// rather than re-typing the action name.
var preApproved = await session.RequestPermissionAsync(addToCalendarTool.ToAction());
Console.WriteLine($"   add_to_calendar : {(preApproved.IsGranted ? "granted" : "denied")} ({preApproved.Reason})");

Section("7. Request a permission for a NON-pre-approved tool");
// `cancel_booking` is not an approved tool, so the PS is consulted and the user
// is prompted to decide. The session threads the mission claim automatically.
var adHoc = await session.RequestPermissionAsync(new MissionAction("cancel_booking"));
Console.WriteLine($"   cancel_booking  : {(adHoc.IsGranted ? "granted" : "denied")} ({adHoc.Reason})");

Section("8. Report an action to the audit endpoint");
// After acting, the agent records what it did under the mission (§Audit Endpoint).
await session.RecordAuditAsync(addToCalendarTool.ToAction(),
    description: "Saved the morning flight to the itinerary.",
    result: new JsonObject { ["status"] = "success" });
Console.WriteLine("   recorded add_to_calendar = success");

Section("9. Ask the user a question");
var answer = await session.AskQuestionAsync(
    "Want me to keep going for another hour?",
    description: "The mission's hour is nearly up.");
Console.WriteLine($"   user answered   : {answer ?? "(no answer)"}");

Section("10. Propose mission completion (terminates the mission)");
var terminated = await session.ProposeCompletionAsync(
    "Trip planned: 3 flights compared, 2 hotels shortlisted, 1 itinerary saved.");
Console.WriteLine($"   mission ended   : {terminated}");

Console.WriteLine();
Console.WriteLine("Done. The Person Server governed every step under the mission.");
return 0;

// ---------------------------------------------------------------------------
// Resource access: the registered agent handles the whole leg.
// ---------------------------------------------------------------------------
async Task<JsonObject?> AccessMissionResourceAsync(string url)
{
    // The agent's client drives the 401 -> token-exchange -> retry cycle, refreshing its
    // agent token at the AP as needed. Naming the mission on the request makes the person
    // token carry its mission_s256, so resource and auth tokens carry it too (#missions);
    // an out-of-scope consent reaches PromptUserAsync. A denied exchange throws
    // AAuthInteractionDeniedException.
    // Showcase only: forget earlier tokens so every step reaches the PS and prints its gate
    // decision. A real agent keeps them; the step-5 scope would then need the resource to
    // step up the cached trips.read token (the SDK's resources answer 403 today).
    tokenCache.Clear();
    using var request = new HttpRequestMessage(HttpMethod.Get, url);
    request.Options.Set(AAuthRequestOptions.MissionS256, mission.S256);
    using var ok = await agent.HttpClient.SendAsync(request);
    ok.EnsureSuccessStatusCode();
    return await ok.Content.ReadFromJsonAsync<JsonObject>();
}

// Invoked when the PS asks the user to decide. Polling proceeds while the user
// acts. Interactive mode opens the PS dashboard once; it lists every request
// waiting for the user, so later prompts only print where to decide. In --auto
// mode the PS resolves the prompt itself, so this is just informational.
Task PromptUserAsync(Interaction interaction, CancellationToken ct)
{
    var url = interaction.BuildUserUrl();
    var hosted = url.StartsWith(personServer + "/interaction?", StringComparison.OrdinalIgnoreCase);
    var dashboard = $"{personServer}/dashboard?code={Uri.EscapeDataString(interaction.Code)}";
    Console.WriteLine();
    Console.WriteLine("   >> The Person Server needs your decision.");
    if (hosted) Console.WriteLine($"      Dashboard: {dashboard}");
    Console.WriteLine($"      {(hosted ? "Or directly" : "Open")}: {url}");
    if (interactive)
    {
        Console.WriteLine("      Waiting for you to Approve or Deny in the browser...");
        if (!hosted) TryOpenBrowser(url);
        else if (!dashboardOpened)
        {
            dashboardOpened = true;
            TryOpenBrowser(dashboard);
        }
    }
    return Task.CompletedTask;
}

async Task ScriptAsync(JsonObject body)
{
    using var resp = await agent.HttpClient.PostAsJsonAsync($"{personServer}/admin/mission-script", body);
    resp.EnsureSuccessStatusCode();
}

void Section(string title)
{
    Console.WriteLine();
    Console.WriteLine($"== {title} ==");
}

static void TryOpenBrowser(string url)
{
    var browser = Environment.GetEnvironmentVariable("BROWSER");
    try
    {
        if (!string.IsNullOrEmpty(browser))
        {
            Process.Start(new ProcessStartInfo(browser, url) { UseShellExecute = false });
        }
        else
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
    }
    catch
    {
        // Headless environment: the printed URL is enough.
    }
}
