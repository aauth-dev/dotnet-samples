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

// Build the HTTP client using the fluent AAuthClientBuilder.
var builder = new AAuthClientBuilder(key).WithEgressPolicy(SampleEgress.Policy);

// Configure signing mode
switch (signingMode)
{
    case "hwk":
        builder.UseHwk();
        break;
    case "jwks":
        var jwksUrl = agentJwksUri ?? $"{apUrl.TrimEnd('/')}/agents/{subject}/jwks.json";
        // Per spec, the receiver looks up the key in the JWKS by `kid`.
        // The AP chooses the kid and returns it as `key_id` at enrollment.
        // If the AP didn't provide one, jwks_uri mode cannot work — the agent
        // has no way to know what kid the AP published the key under.
        if (agentTokenKid is null)
            throw new InvalidOperationException(
                "Cannot use direct jwks: the AP did not return a key_id at enrollment.");
        builder.UseJwks(jwksUrl, agentTokenKid);
        break;
    case "jkt-jwt":
        // Two-key refresh: do initial refresh to get ephemeral key + naming JWT.
        // The durable key signs the naming JWT; the ephemeral key signs HTTP requests.
        var twoKeyResult = await apClient.RefreshTwoKeyAsync(refreshEndpoint, localKeyHandle);
        // Rebuild the builder with the ephemeral key (not the durable key)
        builder = new AAuthClientBuilder(twoKeyResult.EphemeralKey).WithEgressPolicy(SampleEgress.Policy);
        // TODO: In a long-running client, the naming JWT (5-min expiry) and ephemeral key
        // must be regenerated on refresh. For this single-request demo, the initial pair suffices.
        var currentNamingJwt = await NamingJwtBuilder.BuildAsync(key, twoKeyResult.EphemeralKey);
        builder.UseJktJwt(() => currentNamingJwt);
        break;
    default: // "jwt"
        builder = AAuthClientBuilder.Enrolled(key)
            .WithEgressPolicy(SampleEgress.Policy)
            .RefreshingFrom(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .ToBuilder();
        break;
}

// Three-party flows add automatic challenge handling
if (personServer is not null)
{
    builder.WithChallengeHandling(personServer, opts =>
    {
        if (preferWaitSeconds is not null)
            opts.PreferWaitSeconds = preferWaitSeconds;
        opts.MinPollInterval = TimeSpan.FromMilliseconds(200);
        opts.OnPoll = response => Console.WriteLine($"  [poll] {(int)response.StatusCode}");
        opts.OnInteractionRequired = (interaction, ct) =>
        {
            var url = interaction.BuildUserUrl();
            Console.WriteLine($"  [interaction] User approval required: {url}");
            if (url.StartsWith(personServer.TrimEnd('/') + "/interaction?", StringComparison.OrdinalIgnoreCase))
                Console.WriteLine($"  [interaction] Or decide on the PS dashboard: {personServer.TrimEnd('/')}/dashboard?code={Uri.EscapeDataString(interaction.Code)}");
            return Task.CompletedTask;
        };
    });
}

// Call chaining: pass upstream token to downstream exchanges
if (upstreamToken is not null)
{
    builder.WithCallChaining(upstreamToken);
}

if (preferWaitSeconds is not null)
{
    Console.WriteLine($"Prefer: wait={preferWaitSeconds} (long-poll)");
}
if (upstreamToken is not null)
{
    Console.WriteLine("Upstream token provided for call chaining.");
}

// Resource-managed (two-party) opaque-token flow: capture/replay AAuth-Access
// and drive the resource's own consent handshake.
if (resourceManaged)
{
    builder.WithResourceManagedAccess()
        .WithInteractionHandling(opts =>
        {
            opts.MinPollInterval = TimeSpan.FromMilliseconds(200);
            opts.OnInteractionRequired = (consentUrl, code, ct) =>
            {
                Console.WriteLine();
                Console.WriteLine("  [interaction] The resource needs your approval. Open:");
                Console.WriteLine($"    {consentUrl}");
                Console.WriteLine("  Waiting for approval (polling)...");
                return Task.CompletedTask;
            };
        });
}

using var client = builder.Build();

// If the target URL has no path (or just "/"), append the signing-mode-specific
// path. The identity-based modes target the Aria Profile server, whose paths
// describe the *outcome* the resource concludes (not the scheme name); the
// default jwt mode targets the Calendar's three-party `/events` endpoint.
//
//   SIGNING MODE   PROFILE PATH      MEANING
//   hwk        →   /pseudonymous     key thumbprint only (pseudonym)
//   jwks_uri   →   /identified       named, verifiable identity
//   jkt-jwt    →   /anchored         ephemeral key anchored to a durable key
//   jwt        →   /events           three-party Calendar read (calendar.read)
var targetUrl = url;
if (url.AbsolutePath is "/" or "")
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
    Console.WriteLine($"  {header.Key}: {string.Join(", ", header.Value)}");
}

Console.WriteLine();
Console.WriteLine($"Response: {(int)response.StatusCode} {response.ReasonPhrase}");
foreach (var header in response.Headers)
{
    Console.WriteLine($"  {header.Key}: {string.Join(", ", header.Value)}");
}

var body = await response.Content.ReadAsStringAsync();
if (!string.IsNullOrEmpty(body))
{
    Console.WriteLine();
    Console.WriteLine(body);
}

return 0;
