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
    "Usage: MissionAgent [--ap <url>] [--ps <url>] [--resource <url>] [--sub <agent-id>]\n"
    + "                   [--mission-approved <scope>]... [--auto]";

// The scope WhoAmI's /jwt/mission resource demands (and therefore the scope the
// PS gates the token request on). It is mission-approved by default, so steps
// 3-4 resolve silently (gate 2a - InScope).
const string ResourceScope = "whoami";

// The elevated scope WhoAmI's /jwt/mission/elevated resource demands. It is
// deliberately NOT part of the mission's intent, so requesting it prompts the
// user (step 5) unless declared mission-approved as in-scope.
const string ElevatedScope = "whoami:elevated_scope";

string apUrl = "http://localhost:5301";
string personServer = "http://localhost:5100";
string resourceUrl = "http://localhost:5000/jwt/mission";
string subject = "aauth:mission-demo@ap.example";
bool interactive = true;
// Scopes declared as within the mission's intent up front (§Agent Token Request,
// gate 2a). A seeded (resource, scope) pair lets that resource access resolve
// *silently* (reason = InScope) instead of prompting. By default the mission
// approves `whoami`, mirroring the SampleApp mission demo: the WhoAmI token gate
// (steps 3-4) is silent while the elevated scope and the delete_inbox tool still
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
                    // {whoami} set so callers get full control of the in-scope list.
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
// resource's iss is the WhoAmI *origin* (not the /jwt/mission path), so seed
// the in-scope set against the origin to match what the PS will compare.
var resourceOrigin = new Uri(resourceUrl).GetLeftPart(UriPartial.Authority);
bool resourceScopeMissionApproved = missionApprovedScopes.Contains(ResourceScope, StringComparer.Ordinal);
bool elevatedScopeMissionApproved = missionApprovedScopes.Contains(ElevatedScope, StringComparer.Ordinal);

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
var governance = new AAuthGovernanceClient(signedClient, metadata, personServer);
var exchange = new TokenExchangeClient(signedClient, metadata);

// Tell the mock PS how to resolve prompts. Interactive mode holds each prompt
// open until you decide in the browser; --auto resolves via scripted defaults.
// The mission-approved scopes are seeded as in-scope (resource origin, scope)
// pairs so the matching token request resolves silently at gate 2a (§Agent Token
// Request). By default this includes `whoami`, so steps 3-4 never prompt.
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

// Generous polling budget so a human has time to click Approve.
var poller = new DeferredPollerOptions { MaxTotalWait = TimeSpan.FromMinutes(5) };

Section("2. Propose a mission");
// The user approves a durable statement of intent plus the tools the agent may
// use. The PS returns the signed approval blob and its s256 thumbprint, which
// the agent quotes on every later request to bind it to this mission. In
// interactive mode the PS shows a browser consent screen here; in --auto mode it
// resolves the approval itself.
var session = await governance.ProposeMissionAsync(new MissionProposal(
    "Help the user keep their inbox under control for the next hour.")
{
    Tools = new[]
    {
        new MissionTool("send_email", "Send an email on the user's behalf"),
        new MissionTool("summarize", "Summarize a thread"),
    },
}, GovernanceFor("Approve this mission and its tools"));
// The session wraps the approved mission and auto-threads its claim
// (approver + s256) and the bound PS into every later governed call.
var mission = session.Mission;
Console.WriteLine($"   description     : {mission.Description}");
Console.WriteLine($"   approved by     : {mission.Approver}");
Console.WriteLine($"   approved tools  : {string.Join(", ", mission.ApprovedTools.Select(t => t.Name))}");
// The s256 is an RFC 7638-style thumbprint of the signed approval blob, NOT the
// text: tokens carry only {approver, s256} as a compact, verifiable reference
// to the mission above (§Mission Approval). The description/tools stay with the
// approver, so a leaked token never exposes the mission's prose.
Console.WriteLine($"   mission s256    : {mission.S256}  (thumbprint reference to the description above)");

Section(resourceScopeMissionApproved
    ? "3. Access a mission-aware resource — IN SCOPE (silent, no prompt)"
    : "3. Access a mission-aware resource — first call is OUT OF SCOPE");
// WhoAmI's /jwt/mission endpoint is mission-aware: it copies the mission claim
// from the AAuth-Mission header into the resource token it issues (§Terminology).
// The PS reads that claim and governs the token request. When this (resource,
// scope) is mission-approved as in-scope it resolves silently at gate 2a;
// otherwise it falls outside the mission's approved scope and the PS prompts.
if (resourceScopeMissionApproved)
{
    Console.WriteLine($"   mission-approved: {resourceOrigin} / {ResourceScope} is in-scope, so this is granted silently (gate 2a — InScope)");
}
var first = await AccessMissionResourceAsync(resourceUrl);
Console.WriteLine($"   resource said   : access={first?["access"]}, scope={first?["scope"]}");
// The resource echoes only the {approver, s256} reference from the token — the
// same s256 printed in step 2, which maps back to "{mission.Description}".
Console.WriteLine($"   echoed mission  : {first?["mission"]?.ToJsonString()}");
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
// The elevated endpoint demands `whoami:elevated_scope`, a scope the mission
// never declared and whose intent ("keep the inbox under control") does not
// cover it. The PS cannot grant it silently: out-of-mission scopes are NOT
// auto-denied — the PS prompts the user (§Agent Token Request gate 3, §Scopes).
// Approve in the browser and the consent accrues to the mission; deny and the
// exchange throws AAuthInteractionDeniedException (access_denied). Declaring
// whoami:elevated_scope mission-approved (--mission-approved) makes this silent.
if (elevatedScopeMissionApproved)
{
    Console.WriteLine($"   mission-approved: {resourceOrigin} / {ElevatedScope} is in-scope, so this is granted silently (gate 2a — InScope)");
}
var elevatedUrl = $"{resourceOrigin}/jwt/mission/elevated";
try
{
    var elevated = await AccessMissionResourceAsync(elevatedUrl);
    Console.WriteLine($"   resource said   : access={elevated?["access"]}, scope={elevated?["scope"]} (granted after your approval)");
}
catch (AAuthInteractionDeniedException)
{
    Console.WriteLine("   elevated scope  : denied by the user (access_denied) — the gate-2 token is unaffected");
}

Section("6. Request a permission for a pre-approved tool — silent");
// `send_email` is an approved tool, so the SDK short-circuits to granted
// without ever calling the PS (§Permission Endpoint).
var preApproved = await session.RequestPermissionAsync("send_email");
Console.WriteLine($"   send_email      : {(preApproved.IsGranted ? "granted" : "denied")} ({preApproved.Reason})");

Section("7. Request a permission for a NON-pre-approved tool");
// `delete_inbox` is not an approved tool, so the PS is consulted and the user
// is prompted to decide. The session threads the mission claim automatically.
var adHoc = await session.RequestPermissionAsync(
    "delete_inbox",
    options: GovernanceFor("Permission to permanently delete the inbox"));
Console.WriteLine($"   delete_inbox    : {(adHoc.IsGranted ? "granted" : "denied")} ({adHoc.Reason})");

Section("8. Report an action to the audit endpoint");
// After acting, the agent records what it did under the mission (§Audit Endpoint).
await session.RecordAuditAsync("send_email",
    description: "Sent a reply to the design-review thread.",
    result: new JsonObject { ["status"] = "success" });
Console.WriteLine("   recorded send_email = success");

Section("9. Ask the user a question");
var answer = await session.AskQuestionAsync(
    "Want me to keep going for another hour?",
    description: "The mission's hour is nearly up.",
    options: GovernanceFor("A question from your agent"));
Console.WriteLine($"   user answered   : {answer ?? "(no answer)"}");

Section("10. Propose mission completion (terminates the mission)");
var terminated = await session.ProposeCompletionAsync(
    "Inbox triaged: 12 read, 3 replied, 1 deleted.",
    GovernanceFor("Your agent says the mission is done"));
Console.WriteLine($"   mission ended   : {terminated}");

Console.WriteLine();
Console.WriteLine("Done. The Person Server governed every step under the mission.");
return 0;

// ---------------------------------------------------------------------------
// Resource access: challenge -> token exchange (governed by the PS) -> retry.
// ---------------------------------------------------------------------------
async Task<JsonObject?> AccessMissionResourceAsync(string url)
{
    // A real agent rotates its short-lived agent token; refreshing here gives
    // each request a fresh `jti`, which also satisfies the resource's replay
    // detection (§HTTP Message Signatures — replay).
    agentToken = await apClient.RefreshAsync(refreshEndpoint, localKeyHandle);

    // 1. Signed request carrying the mission. The signing handler covers the
    //    aauth-mission header automatically, so the resource can trust it.
    var challengeReq = new HttpRequestMessage(HttpMethod.Get, url);
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
    using var ok = await authClient.GetAsync(url);
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
