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
    "[--ps <person-server-url>] [--signing-mode jwt|hwk|jwks_uri|jkt-jwt] " +
    "[--prefer-wait <seconds>] [--upstream-token <jwt>]";

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
    else
    {
        Console.Error.WriteLine($"Unknown argument: {flag}");
        return 1;
    }
}

// Default: jwt for three-party (with PS), hwk for identity-based (no PS).
signingMode ??= personServer is not null ? "jwt" : "hwk";

if (signingMode is not ("jwt" or "hwk" or "jwks_uri" or "jkt-jwt"))
{
    Console.Error.WriteLine($"Unknown signing mode: {signingMode}. Must be jwt, hwk, jwks_uri, or jkt-jwt.");
    return 1;
}

if (personServer is not null && signingMode is not "jwt")
{
    Console.Error.WriteLine("Three-party flows (--ps) require --signing-mode jwt.");
    Console.Error.WriteLine("Pseudonymous modes (hwk, jwks_uri, jkt-jwt) are for identity-based access only.");
    return 1;
}

if (personServer is null && signingMode is "jwt")
{
    Console.Error.WriteLine("Agent Token mode (jwt) requires a Person Server (--ps).");
    Console.Error.WriteLine("For identity-based access without a PS, use --signing-mode hwk, jwks_uri, or jkt-jwt.");
    return 1;
}

if (apUrl is null)
{
    Console.Error.WriteLine("--ap <agent-provider-url> is required.");
    Console.Error.WriteLine(Usage);
    return 1;
}

IAAuthKey key;
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
    // Bootstrap with the Agent Provider: discover endpoints from metadata
    var apBase = apUrl.TrimEnd('/');
    Console.WriteLine($"Discovering Agent Provider metadata at: {apBase}");
    var discoveryClient = new MetadataClient(new HttpClient());
    var metaUrl = MetadataClient.BuildUrl(apBase, "aauth-agent.json");
    var apMeta = await discoveryClient.FetchAsync(metaUrl);
    var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apBase}/enrol";
    refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apBase}/refresh";
    Console.WriteLine($"Enrolling at: {enrolEndpoint}");

    var apClient = new AgentProviderClient(new HttpClient(), keyStore);
    var result = await apClient.EnrolAsync(apBase, subject, enrolEndpoint, personServer);
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
}

Console.WriteLine($"Using key handle: {localKeyHandle}");
Console.WriteLine($"Public JWK thumbprint: {key.ComputeJwkThumbprint()}");
Console.WriteLine();

Console.WriteLine($"Signing mode: {signingMode}");

// Build the HTTP client using the fluent AAuthClientBuilder.
var builder = new AAuthClientBuilder(key);

// Configure signing mode
switch (signingMode)
{
    case "hwk":
        builder.UseHwk();
        break;
    case "jwks_uri":
        var jwksUrl = agentJwksUri ?? $"{apUrl.TrimEnd('/')}/agents/{subject}/jwks.json";
        // Per spec, the receiver looks up the key in the JWKS by `kid`.
        // The AP chooses the kid and returns it as `key_id` at enrollment.
        // If the AP didn't provide one, jwks_uri mode cannot work — the agent
        // has no way to know what kid the AP published the key under.
        if (agentTokenKid is null)
            throw new InvalidOperationException(
                "Cannot use jwks_uri signing mode: the AP did not return a key_id at enrollment. " +
                "Re-enrol with an AP that supports jwks_uri identity.");
        builder.UseJwksUri(jwksUrl, agentTokenKid);
        break;
    case "jkt-jwt":
        // Two-key refresh: do initial refresh to get ephemeral key + naming JWT.
        // The durable key signs the naming JWT; the ephemeral key signs HTTP requests.
        var twoKeyClient = new AgentProviderClient(new HttpClient(), keyStore);
        var twoKeyResult = twoKeyClient.RefreshTwoKeyAsync(
            refreshEndpoint, localKeyHandle, apUrl.TrimEnd('/')).GetAwaiter().GetResult();
        // Rebuild the builder with the ephemeral key (not the durable key)
        builder = new AAuthClientBuilder(twoKeyResult.EphemeralKey);
        // TODO: In a long-running client, the naming JWT (5-min expiry) and ephemeral key
        // must be regenerated on refresh. For this single-request demo, the initial pair suffices.
        var currentNamingJwt = NamingJwtBuilder.Build(
            key, twoKeyResult.EphemeralKey, apUrl.TrimEnd('/'), key.ComputeJwkThumbprint());
        builder.UseJktJwt(() => currentNamingJwt);
        // Three-party challenge handling uses the refreshed agent token
        if (personServer is not null)
        {
            builder.WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
                .WithKeyStore(keyStore)
                .WithRefreshMode(RefreshMode.TwoKey, apUrl.TrimEnd('/'))
                .Build());
        }
        break;
    default: // "jwt"
        builder.WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
            .WithKeyStore(keyStore)
            .Build());
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
            Console.WriteLine($"  [interaction] User approval required: {interaction.BuildUserUrl()}");
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

using var client = builder.Build();

// If the target URL has no path (or just "/"), append the signing-mode-specific
// path so the WhoAmI sample routes to the correct verification middleware.
var targetUrl = url;
if (url.AbsolutePath is "/" or "")
{
    targetUrl = signingMode switch
    {
        "hwk" => new Uri(url, "/hwk"),
        "jkt-jwt" => new Uri(url, "/jkt-jwt"),
        "jwks_uri" => new Uri(url, "/jwks-uri"),
        _ => new Uri(url, "/jwt"), // jwt → three-party baseline endpoint
    };
}

var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
Console.WriteLine($"GET {targetUrl}");

HttpResponseMessage response;
try
{
    response = await client.SendAsync(request);
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
