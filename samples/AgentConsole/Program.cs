using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

const string Usage = "Usage: AgentConsole <url> --ap <agent-provider-url> [--sub <agent-id>] " +
    "[--ps <person-server-url>] [--signing-mode jwt|hwk|jwks|jkt-jwt] " +
    "[--resource-managed] [--prefer-wait <seconds>] [--upstream-token <jwt>]";

if (args.Length < 1 || args[0] is "--help" or "-h")
{
    Console.Error.WriteLine(Usage);
    return args.Length < 1 ? 1 : 0;
}

if (args[0].StartsWith("--", StringComparison.Ordinal))
{
    Console.Error.WriteLine("First argument must be a URL.");
    Console.Error.WriteLine(Usage);
    return 1;
}

if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
{
    Console.Error.WriteLine($"Invalid URL: {args[0]}");
    return 1;
}

string subject = "aauth:demo@ap.example";
string? personServer = null;
string? apUrl = null;
string? signingMode = null;
int? preferWaitSeconds = null;
string? upstreamToken = null;
bool resourceManaged = false;
for (int i = 1; i < args.Length; i++)
{
    string flag = args[i];
    if (flag is "--sub" or "--ps" or "--ap" or "--signing-mode" or "--prefer-wait" or "--upstream-token")
    {
        if (i + 1 >= args.Length)
        {
            Console.Error.WriteLine($"Missing value for {flag}.");
            return 1;
        }
        var value = args[++i];
        switch (flag)
        {
            case "--sub": subject = value; break;
            case "--ps":  personServer = value; break;
            case "--ap":  apUrl = value; break;
            case "--signing-mode": signingMode = value; break;
            case "--prefer-wait":
                if (!int.TryParse(value, out var pw) || pw < 0)
                {
                    Console.Error.WriteLine($"--prefer-wait must be a non-negative integer.");
                    return 1;
                }
                preferWaitSeconds = pw;
                break;
            case "--upstream-token": upstreamToken = value; break;
        }
    }
    else if (flag is "--resource-managed")
    {
        resourceManaged = true;
    }
    else
    {
        Console.Error.WriteLine($"Unknown argument: {flag}");
        return 1;
    }
}

signingMode ??= "jwt";

if (signingMode is not ("jwt" or "hwk" or "jwks" or "jkt-jwt"))
{
    Console.Error.WriteLine($"Unknown signature scheme: {signingMode}. Must be jwt, hwk, jwks, or jkt-jwt.");
    return 1;
}

if ((personServer is not null || resourceManaged) && signingMode is not "jwt")
{
    Console.Error.WriteLine("AAuth resource-managed and PS flows require --signing-mode jwt.");
    Console.Error.WriteLine("Other schemes are generic Signature Keys demonstrations, not AAuth resource access modes.");
    return 1;
}

if (resourceManaged && personServer is not null)
{
    Console.Error.WriteLine("Resource-managed (--resource-managed) is a two-party flow; do not pass --ps.");
    return 1;
}

if (apUrl is null)
{
    Console.Error.WriteLine("--ap <agent-provider-url> is required.");
    Console.Error.WriteLine(Usage);
    return 1;
}

IAAuthSigner key;
string localKeyHandle;
string? agentTokenKid;
string? agentJwksUri;
string refreshEndpoint;

// Per spec, agent keys are long-lived (spanning the agent install).
// The key lives in a durable keystore — we only persist its handle + AP metadata.
IKeyStore keyStore = FileKeyStore.Default();

var enrollCacheFile = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "aauth-agent-console", $"{subject}.json");

if (File.Exists(enrollCacheFile))
{
    var cached = JsonNode.Parse(File.ReadAllText(enrollCacheFile))!;
    localKeyHandle = (string)cached["key_id"]!;
    agentTokenKid = (string?)cached["agent_token_kid"];
    agentJwksUri = (string?)cached["jwks_uri"];
    refreshEndpoint = (string)cached["refresh_endpoint"]!;

    key = await keyStore.LoadAsync(localKeyHandle)
        ?? throw new InvalidOperationException($"Key '{localKeyHandle}' not found in store. Delete {enrollCacheFile} and re-enrol.");
    Console.WriteLine($"Loaded enrolled agent. Local key handle: {localKeyHandle}");
}
else
{
    key = AAuthKey.Generate();
}

// Bootstrap with the Agent Provider: discover endpoints from metadata
var apBase = apUrl.TrimEnd('/');
Console.WriteLine($"Discovering Agent Provider metadata at: {apBase}");
using var apHttp = new SampleHttpClient();
using var discoveryClient = new MetadataClient(apHttp);
var metaUrl = MetadataClient.BuildUrl(apBase, "aauth-agent.json", SampleEgress.Policy);
var apMeta = await discoveryClient.FetchAsync(metaUrl);
var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apBase}/enrol";
refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apBase}/refresh";
Console.WriteLine($"Enrolling at: {enrolEndpoint}");

var apClient = new AgentProviderClient(apHttp, keyStore);
var result = await apClient.EnrolWithKeyAsync(apBase, null, enrolEndpoint, (AAuthKey)key, personServer);
key = result.Key;
localKeyHandle = result.LocalKeyHandle;
agentTokenKid = result.AgentTokenKid;
agentJwksUri = result.JwksUri;
Console.WriteLine($"Enrolled successfully. Local key handle: {localKeyHandle}");
// Consent is recorded for the AP-assigned identity, not the --sub cache label.
Console.WriteLine($"Agent ID (AP-assigned): {result.AgentId}");

// Persist only metadata — key lives in the keystore, token is short-lived
Directory.CreateDirectory(Path.GetDirectoryName(enrollCacheFile)!);
File.WriteAllText(enrollCacheFile, JsonSerializer.Serialize(new
{
    key_id = localKeyHandle,
    agent_token_kid = agentTokenKid,
    jwks_uri = agentJwksUri,
    refresh_endpoint = refreshEndpoint,
}));

Console.WriteLine($"Using key handle: {localKeyHandle}");
Console.WriteLine($"Public JWK thumbprint: {key.ComputeJwkThumbprint()}");
Console.WriteLine();

Console.WriteLine($"Signature scheme: {signingMode}");

// A generic host owns the agent. The jwt mode is a registered agent: the SDK refreshes its
// agent token at the AP with the durable key and handles challenges, chaining and
// resource-managed access from options. The other schemes demonstrate a Signature-Key mode
// itself, so they compose the builder primitive and the factory owns the result.
var hostBuilder = Host.CreateApplicationBuilder();
hostBuilder.Logging.ClearProviders();
hostBuilder.Services.AddSingleton(keyStore);
hostBuilder.Services.AddAAuthAgentFactory();
if (signingMode is "jwt")
{
    hostBuilder.Services.AddAAuthAgent("console", options =>
    {
        options.KeyHandle = localKeyHandle;
        options.AgentProvider.RefreshEndpoint = refreshEndpoint;
        options.EgressPolicy = SampleEgress.Policy;
        if (personServer is not null)
        {
            // Three-party flows add automatic challenge handling.
            options.PersonServer = personServer;
            options.Challenge.PreferWaitSeconds = preferWaitSeconds;
            options.Challenge.MinPollInterval = TimeSpan.FromMilliseconds(200);
            options.Challenge.OnPoll = response => Console.WriteLine($"  [poll] {(int)response.StatusCode}");
            options.Challenge.OnInteractionRequired = (interaction, ct) =>
            {
                var url = interaction.BuildUserUrl();
                Console.WriteLine($"  [interaction] User approval required: {url}");
                if (url.StartsWith(personServer.TrimEnd('/') + "/interaction?", StringComparison.OrdinalIgnoreCase))
                    Console.WriteLine($"  [interaction] Or decide on the PS dashboard: {personServer.TrimEnd('/')}/dashboard?code={Uri.EscapeDataString(interaction.Code)}");
                return Task.CompletedTask;
            };
        }
        // Call chaining: pass the upstream token to downstream exchanges.
        if (upstreamToken is not null) options.UpstreamTokenProvider = () => upstreamToken;
        if (resourceManaged)
        {
            // Resource-managed (two-party) opaque-token flow: capture/replay AAuth-Access.
            options.EnableResourceManagedAccess = true;
        }
        if (resourceManaged || personServer is not null)
        {
            // A resource may itself defer with 202 + requirement=interaction: its own
            // consent (resource-managed Inbox) or a downstream hop's consent relayed
            // by an intermediary (the Concierge call chain).
            options.HandleInteractions = true;
            options.Interaction.MinPollInterval = TimeSpan.FromMilliseconds(200);
            options.Interaction.OnInteractionRequired = (interaction, ct) =>
            {
                Console.WriteLine();
                Console.WriteLine("  [interaction] The resource needs your approval. Open:");
                Console.WriteLine($"    {interaction.BuildUserUrl()}");
                Console.WriteLine("  Waiting for approval (polling)...");
                return Task.CompletedTask;
            };
        }
    });
}
using var host = hostBuilder.Build();
var agents = host.Services.GetRequiredService<IAAuthAgentFactory>();

using var agent = signingMode switch
{
    "hwk" => agents.Create("console", key, builder => builder.WithEgressPolicy(SampleEgress.Policy).UseHwk()),
    "jwks" => agents.Create("console", key, builder => builder.WithEgressPolicy(SampleEgress.Policy)
        // Per spec, the receiver looks up the key in the JWKS by `kid`. The AP chooses the kid
        // and returns it as `key_id` at enrollment; without it jwks_uri mode cannot work.
        .UseJwks(agentJwksUri ?? $"{apUrl.TrimEnd('/')}/agents/{subject}/jwks.json",
            agentTokenKid ?? throw new InvalidOperationException(
                "Cannot use direct jwks: the AP did not return a key_id at enrollment."))),
    "jkt-jwt" => await JktJwtAgentAsync(),
    _ => agents.Get("console"),
};
var client = agent.HttpClient;

// Two-key refresh: the durable key signs the naming JWT; the ephemeral key signs HTTP requests.
// In a long-running client the naming JWT (5-min expiry) and ephemeral key must be regenerated
// on refresh. For this single-request demo, the initial pair suffices.
async Task<AAuthAgent> JktJwtAgentAsync()
{
    var twoKeyResult = await apClient.RefreshTwoKeyAsync(refreshEndpoint, localKeyHandle);
    var currentNamingJwt = await NamingJwtBuilder.BuildAsync(key, twoKeyResult.EphemeralKey);
    return agents.Create("console", twoKeyResult.EphemeralKey, builder => builder
        .WithEgressPolicy(SampleEgress.Policy).UseJktJwt(() => currentNamingJwt));
}

if (preferWaitSeconds is not null)
{
    Console.WriteLine($"Prefer: wait={preferWaitSeconds} (long-poll)");
}
if (upstreamToken is not null)
{
    Console.WriteLine("Upstream token provided for call chaining.");
}

// If the target URL has no path at all, append the signing-mode-specific
// path. An explicit trailing "/" (e.g. http://localhost:5200/ for the
// Concierge chain) targets the root instead. The identity-based modes target
// the Aria Profile server, whose paths describe the *outcome* the resource
// concludes (not the scheme name); the default jwt mode targets the
// Calendar's three-party `/events` endpoint.
//
//   SIGNING MODE   PROFILE PATH      MEANING
//   hwk        →   /pseudonymous     key thumbprint only (pseudonym)
//   jwks_uri   →   /identified       named, verifiable identity
//   jkt-jwt    →   /anchored         ephemeral key anchored to a durable key
//   jwt        →   /events           three-party Calendar read (calendar.read)
var targetUrl = url;
var typedPath = args[0][(args[0].IndexOf("://", StringComparison.Ordinal) + 3)..];
if (url.AbsolutePath == "/" && !typedPath.Contains('/'))
{
    targetUrl = resourceManaged
        ? new Uri(url, "/messages") // resource-managed two-party (Inbox)
        : signingMode switch
        {
            "hwk" => new Uri(url, "/pseudonymous"),
            "jkt-jwt" => new Uri(url, "/anchored"),
            "jwks" => new Uri(url, "/identified"),
            _ => new Uri(url, "/events"), // jwt → three-party baseline endpoint
        };
}

HttpRequestMessage request;
HttpResponseMessage response;
try
{
    if (resourceManaged)
    {
        // First call drives the 202 → consent → poll handshake; the SDK captures
        // the issued AAuth-Access token.
        Console.WriteLine($"GET {targetUrl} (initial — may require consent)");
        using (var first = await client.GetAsync(targetUrl))
        {
            Console.WriteLine($"  → {(int)first.StatusCode} {first.ReasonPhrase}");
        }

        // Second call replays Authorization: AAuth, bound to the signature.
        Console.WriteLine($"GET {targetUrl} (replaying AAuth-Access)");
        request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
        response = await client.SendAsync(request);
    }
    else
    {
        request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
        Console.WriteLine($"GET {targetUrl}");
        response = await client.SendAsync(request);
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Request failed: {ex.Message}");
    return 2;
}

Console.WriteLine();
Console.WriteLine("Request headers:");
foreach (var header in request.Headers)
{
    Console.WriteLine($"  {header.Key}: {RedactHeader(header.Key, string.Join(", ", header.Value))}");
}

Console.WriteLine();
Console.WriteLine($"Response: {(int)response.StatusCode} {response.ReasonPhrase}");
foreach (var header in response.Headers)
{
    Console.WriteLine($"  {header.Key}: {RedactHeader(header.Key, string.Join(", ", header.Value))}");
}

var body = await response.Content.ReadAsStringAsync();
if (!string.IsNullOrEmpty(body))
{
    Console.WriteLine();
    Console.WriteLine(RedactProtocolArtifacts(body));
}

return 0;

static string RedactHeader(string name, string value)
    => name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Signature-Key", StringComparison.OrdinalIgnoreCase)
        || name.Equals("AAuth-Requirement", StringComparison.OrdinalIgnoreCase)
        || name.Equals("AAuth-Access", StringComparison.OrdinalIgnoreCase)
            ? "[redacted protocol credential]"
            : RedactProtocolArtifacts(value);

static string RedactProtocolArtifacts(string value)
    => System.Text.RegularExpressions.Regex.Replace(
        value,
        @"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])",
        "[redacted compact JWT]");
