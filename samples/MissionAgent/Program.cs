using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;

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
//   MockAgentProvider (:5301) -> MockPersonServer (:5100) -> WhoAmI (:5000)
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
    "Usage: MissionAgent [--ap <url>] [--ps <url>] [--resource <url>] [--sub <agent-id>] [--auto]";

string apUrl = "http://localhost:5301";
string personServer = "http://localhost:5100";
string resourceUrl = "http://localhost:5000/jwt/mission";
string subject = "aauth:mission-demo@ap.example";
bool interactive = true;

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
        case "--ap" or "--ps" or "--resource" or "--sub":
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

Section("1. Enrol with the Agent Provider");
// The agent's signing key is long-lived (it spans the agent install). The
// keystore holds the private key; we keep only its handle in memory here.
IKeyStore keyStore = FileKeyStore.Default();
var discovery = new MetadataClient(new HttpClient());
var apMeta = await discovery.FetchAsync(MetadataClient.BuildUrl(apUrl, "aauth-agent.json"));
var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apUrl}/enrol";
var refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apUrl}/refresh";

var apClient = new AgentProviderClient(new HttpClient(), keyStore);
var enrolment = await apClient.EnrolAsync(apUrl, subject, enrolEndpoint, personServer);
AAuthKey key = enrolment.Key;
string localKeyHandle = enrolment.LocalKeyHandle;
string agentToken = enrolment.AgentToken;
Console.WriteLine($"   agent id        : {subject}");
Console.WriteLine($"   key thumbprint  : {key.ComputeJwkThumbprint()}");
Console.WriteLine($"   person server   : {personServer}");

// Signed channel for agent-token requests: the resource challenge, the token
// exchange, and every governance call (mission/permission/audit/interaction)
// flow over this handler, which signs each request and carries the agent token
// in the Signature-Key header (§HTTP Message Signatures).
var agentHandler = new AAuthSigningHandler(key, () => agentToken) { InnerHandler = new HttpClientHandler() };
var signedClient = new HttpClient(agentHandler) { Timeout = Timeout.InfiniteTimeSpan };
var metadata = new MetadataClient(new HttpClient());
var governance = new AAuthGovernanceClient(signedClient, metadata);
var exchange = new TokenExchangeClient(signedClient, metadata);

// Tell the mock PS how to resolve prompts. Interactive mode holds each prompt
// open until you decide in the browser; --auto resolves via scripted defaults.
await ScriptAsync(new JsonObject
{
    ["reset"] = true,
    ["interactive"] = interactive,
    ["approveMission"] = true,
    ["approveToken"] = true,
    ["approvePermission"] = true,
});
Console.WriteLine($"   prompt mode     : {(interactive ? "interactive (decide in your browser)" : "auto (scripted approvals)")}");

// Generous polling budget so a human has time to click Approve.
var poller = new DeferredPollerOptions { MaxTotalWait = TimeSpan.FromMinutes(5) };

Section("2. Propose a mission");
// The user approves a durable statement of intent plus the tools the agent may
// use. The PS returns the signed approval blob and its s256 thumbprint, which
// the agent quotes on every later request to bind it to this mission. In
// interactive mode the PS shows a browser consent screen here; in --auto mode it
// resolves the approval itself.
var mission = await governance.Mission.ProposeAsync(personServer, new MissionProposal(
    "Help the user keep their inbox under control for the next hour.")
{
    Tools = new[]
    {
        new MissionTool("send_email", "Send an email on the user's behalf"),
        new MissionTool("summarize", "Summarize a thread"),
    },
}, GovernanceFor("Approve this mission and its tools"));
var missionClaim = new MissionClaim(mission.Approver, mission.S256);
Console.WriteLine($"   description     : {mission.Description}");
Console.WriteLine($"   approved by     : {mission.Approver}");
Console.WriteLine($"   approved tools  : {string.Join(", ", mission.ApprovedTools.Select(t => t.Name))}");
// The s256 is an RFC 7638-style thumbprint of the signed approval blob, NOT the
// text: tokens carry only {approver, s256} as a compact, verifiable reference
// to the mission above (§Mission Approval). The description/tools stay with the
// approver, so a leaked token never exposes the mission's prose.
Console.WriteLine($"   mission s256    : {mission.S256}  (thumbprint reference to the description above)");

Section("3. Access a mission-aware resource — first call is OUT OF SCOPE");
// WhoAmI's /jwt/mission endpoint is mission-aware: it copies the mission claim
// from the AAuth-Mission header into the resource token it issues (§Terminology).
// The PS reads that claim and governs the token request. This (resource, scope)
// is not in the mission's pre-approved scope, so the PS prompts the user.
var first = await AccessMissionResourceAsync();
Console.WriteLine($"   resource said   : access={first?["access"]}, scope={first?["scope"]}");
// The resource echoes only the {approver, s256} reference from the token — the
// same s256 printed in step 2, which maps back to "{mission.Description}".
Console.WriteLine($"   echoed mission  : {first?["mission"]?.ToJsonString()}");
Console.WriteLine($"                     (s256 references: \"{mission.Description}\")");

Section("4. Access it again — now silent via PRIOR CONSENT");
// The same (resource, scope) was just approved under this mission, so the PS
// grants the token silently this time (gate 2b) — no prompt.
var second = await AccessMissionResourceAsync();
Console.WriteLine($"   resource said   : access={second?["access"]}, scope={second?["scope"]} (granted silently)");

Section("5. Request a permission for a pre-approved tool — silent");
// `send_email` is an approved tool, so the SDK short-circuits to granted
// without ever calling the PS (§Permission Endpoint).
var preApproved = await governance.Permission.RequestAsync(personServer, "send_email", mission);
Console.WriteLine($"   send_email      : {(preApproved.IsGranted ? "granted" : "denied")} ({preApproved.Reason})");

Section("6. Request a permission for a NON-pre-approved tool");
// `delete_inbox` is not an approved tool, so the PS is consulted and the user
// is prompted to decide.
var adHoc = await governance.Permission.RequestAsync(
    personServer,
    new PermissionRequest("delete_inbox") { Mission = missionClaim },
    GovernanceFor("Permission to permanently delete the inbox"));
Console.WriteLine($"   delete_inbox    : {(adHoc.IsGranted ? "granted" : "denied")} ({adHoc.Reason})");

Section("7. Report an action to the audit endpoint");
// After acting, the agent records what it did under the mission (§Audit Endpoint).
await governance.Audit.RecordAsync(personServer, new AuditRecord(missionClaim, "send_email")
{
    Description = "Sent a reply to the design-review thread.",
    Result = new JsonObject { ["status"] = "success" },
});
Console.WriteLine("   recorded send_email = success");

Section("8. Ask the user a question");
var answer = await governance.Interaction.AskQuestionAsync(
    personServer,
    "Want me to keep going for another hour?",
    description: "The mission's hour is nearly up.",
    mission: missionClaim,
    options: GovernanceFor("A question from your agent"));
Console.WriteLine($"   user answered   : {answer ?? "(no answer)"}");

Section("9. Propose mission completion (terminates the mission)");
var terminated = await governance.Interaction.ProposeCompletionAsync(
    personServer,
    "Inbox triaged: 12 read, 3 replied, 1 deleted.",
    missionClaim,
    GovernanceFor("Your agent says the mission is done"));
Console.WriteLine($"   mission ended   : {terminated}");

Console.WriteLine();
Console.WriteLine("Done. The Person Server governed every step under the mission.");
return 0;

// ---------------------------------------------------------------------------
// Resource access: challenge -> token exchange (governed by the PS) -> retry.
// ---------------------------------------------------------------------------
async Task<JsonObject?> AccessMissionResourceAsync()
{
    // A real agent rotates its short-lived agent token; refreshing here gives
    // each request a fresh `jti`, which also satisfies the resource's replay
    // detection (§HTTP Message Signatures — replay).
    agentToken = await apClient.RefreshAsync(refreshEndpoint, localKeyHandle);

    // 1. Signed request carrying the mission. The signing handler covers the
    //    aauth-mission header automatically, so the resource can trust it.
    var challengeReq = new HttpRequestMessage(HttpMethod.Get, resourceUrl);
    challengeReq.Headers.TryAddWithoutValidation(
        AAuthMissionHeader.Name, AAuthMissionHeader.FormatStructured(mission.Approver, mission.S256));
    using var challenge = await signedClient.SendAsync(challengeReq);
    if (challenge.StatusCode != HttpStatusCode.Unauthorized)
    {
        throw new InvalidOperationException(
            $"Expected 401 challenge from the resource, got {(int)challenge.StatusCode}.");
    }

    // 2. Parse the AAuth-Requirement header to recover the resource token.
    var requirement = string.Join(", ", challenge.Headers.GetValues(AAuthRequirementHeader.Name));
    var parsed = AAuthRequirementHeader.Parse(requirement);
    var resourceToken = parsed.ResourceToken
        ?? throw new InvalidOperationException("Challenge did not carry a resource token.");

    // 3. Exchange the resource token at the PS. The PS reads the mission claim
    //    embedded in the (verified) resource token and applies the token gate;
    //    an out-of-scope request returns 202 and we print the consent URL.
    var authToken = await exchange.ExchangeAsync(personServer, resourceToken, new TokenExchangeRequest
    {
        OnInteractionRequired = PromptUserAsync,
        PollerOptions = poller,
    });

    // 4. Replay the request with the auth token to obtain the protected resource.
    var authHandler = new AAuthSigningHandler(key, () => authToken) { InnerHandler = new HttpClientHandler() };
    using var authClient = new HttpClient(authHandler);
    using var ok = await authClient.GetAsync(resourceUrl);
    ok.EnsureSuccessStatusCode();
    return await ok.Content.ReadFromJsonAsync<JsonObject>();
}

// Build governance options that prompt interactively (or stay scripted).
GovernanceOptions GovernanceFor(string _) => new()
{
    OnInteractionRequired = PromptUserAsync,
    PollerOptions = poller,
};

// Invoked when the PS asks the user to decide. In interactive mode we surface
// the consent URL (and try to open it) and return — polling proceeds while the
// user acts. In --auto mode the PS resolves the prompt itself, so this is just
// informational.
Task PromptUserAsync(Interaction interaction, CancellationToken ct)
{
    var url = interaction.BuildUserUrl();
    Console.WriteLine();
    Console.WriteLine("   >> The Person Server needs your decision.");
    Console.WriteLine($"      Open: {url}");
    if (interactive)
    {
        Console.WriteLine("      Waiting for you to Approve or Deny in the browser...");
        TryOpenBrowser(url);
    }
    return Task.CompletedTask;
}

async Task ScriptAsync(JsonObject body)
{
    using var resp = await signedClient.PostAsJsonAsync($"{personServer}/admin/mission-script", body);
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
