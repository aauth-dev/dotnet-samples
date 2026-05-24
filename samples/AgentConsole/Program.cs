using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;

const string Usage = "Usage: AgentConsole <url> --ap <agent-provider-url> [--sub <agent-id>] " +
    "[--kid <key-id>] [--ps <person-server-url>] [--signing-mode jwt|hwk|jwks_uri]";

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
for (int i = 1; i < args.Length; i++)
{
    string flag = args[i];
    if (flag is "--sub" or "--ps" or "--ap" or "--signing-mode")
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

if (signingMode is not ("jwt" or "hwk" or "jwks_uri"))
{
    Console.Error.WriteLine($"Unknown signing mode: {signingMode}. Must be jwt, hwk, or jwks_uri.");
    return 1;
}

if (personServer is not null && signingMode is not "jwt")
{
    Console.Error.WriteLine("Three-party flows (--ps) require --signing-mode jwt per spec.");
    Console.Error.WriteLine("Non-jwt modes (hwk, jwks_uri) are for identity-based access only.");
    return 1;
}

if (personServer is null && signingMode is "jwt")
{
    Console.Error.WriteLine("Agent Token mode (jwt) requires a Person Server (--ps).");
    Console.Error.WriteLine("For identity-based access without a PS, use --signing-mode hwk or jwks_uri.");
    return 1;
}

if (apUrl is null)
{
    Console.Error.WriteLine("--ap <agent-provider-url> is required.");
    Console.Error.WriteLine(Usage);
    return 1;
}

IAAuthKey key;
string keyId;
string? agentJwksUri;
string refreshEndpoint;

// Per spec, agent keys are long-lived (spanning the agent install).
// The key lives in a durable keystore — we only persist its ID + AP metadata.
IKeyStore keyStore = KeyStore.Default();

var enrollCacheFile = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "aauth-agent-console", $"{subject}.json");

if (File.Exists(enrollCacheFile))
{
    var cached = JsonNode.Parse(File.ReadAllText(enrollCacheFile))!;
    keyId = (string)cached["key_id"]!;
    agentJwksUri = (string?)cached["jwks_uri"];
    refreshEndpoint = (string)cached["refresh_endpoint"]!;

    key = await keyStore.LoadAsync(keyId)
        ?? throw new InvalidOperationException($"Key '{keyId}' not found in store. Delete {enrollCacheFile} and re-enrol.");
    Console.WriteLine($"Loaded enrolled agent. Key ID: {keyId}");
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
    keyId = result.KeyId;
    agentJwksUri = result.JwksUri;
    Console.WriteLine($"Enrolled successfully. Key ID: {keyId}");

    // Persist only metadata — key lives in the keystore, token is short-lived
    Directory.CreateDirectory(Path.GetDirectoryName(enrollCacheFile)!);
    File.WriteAllText(enrollCacheFile, JsonSerializer.Serialize(new
    {
        key_id = keyId,
        jwks_uri = agentJwksUri,
        refresh_endpoint = refreshEndpoint,
    }));
}

Console.WriteLine($"Using key: {keyId}");
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
        builder.UseJwksUri(jwksUrl, keyId);
        break;
    default: // "jwt"
        var endpoint = refreshEndpoint;
        var refreshKeyId = keyId; // AP-assigned key ID (matches keystore)
        builder.WithTokenRefresh(async (ctx, ct) =>
        {
            var apClient = new AgentProviderClient(new HttpClient(), keyStore);
            return await apClient.RefreshAsync(endpoint, refreshKeyId, ct);
        });
        break;
}

// Three-party flows add automatic challenge handling
if (personServer is not null)
{
    builder.WithChallengeHandling(personServer);
}

using var client = builder.Build();

var request = new HttpRequestMessage(HttpMethod.Get, url);
Console.WriteLine($"GET {url}");

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
