using System;
using System.Net.Http;
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

AAuthKey key;
string agentToken;
string keyId;

// Bootstrap with the Agent Provider: discover enrol_endpoint from metadata
var apBase = apUrl.TrimEnd('/');
Console.WriteLine($"Discovering Agent Provider metadata at: {apBase}");
var discoveryClient = new MetadataClient(new HttpClient());
var metaUrl = MetadataClient.BuildUrl(apBase, "aauth-agent.json");
var apMeta = await discoveryClient.FetchAsync(metaUrl);
var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apBase}/enrol";
Console.WriteLine($"Enrolling at: {enrolEndpoint}");

var apKeyStore = new InMemoryKeyStore();
var apClient = new AgentProviderClient(new HttpClient(), apKeyStore);
var result = await apClient.EnrolAsync(apBase, subject, enrolEndpoint, personServer);
key = result.Key;
agentToken = result.AgentToken;
keyId = result.KeyId;
Console.WriteLine($"Enrolled successfully. Key ID: {keyId}");

Console.WriteLine($"Using key: {keyId}");
Console.WriteLine($"Public JWK thumbprint: {key.ComputeJwkThumbprint()}");
Console.WriteLine();
Console.WriteLine("Agent token:");
Console.WriteLine(agentToken);
Console.WriteLine();

// Shared carrier-token holder. The signing handler reads from it on every
// request; the challenge handler updates it when an auth-token is issued.
var tokenHolder = new AAuthTokenHolder(agentToken);

ISignatureKeyProvider BuildProvider(Func<string> tokenSource) => signingMode switch
{
    "hwk" => new HwkSignatureKeyProvider(key),
    "jwks_uri" => new JwksUriSignatureKeyProvider(
        $"{apBase}/.well-known/jwks.json", keyId),
    _ => new JwtSignatureKeyProvider(tokenSource),
};

HttpMessageHandler BuildSigningPipeline(Func<string> tokenSource) =>
    new AAuthSigningHandler(key, BuildProvider(tokenSource))
    {
        InnerHandler = new HttpClientHandler(),
    };

Console.WriteLine($"Signing mode: {signingMode}");

// Resource client: ChallengeHandler on top when a PS is configured,
// otherwise just the signing pipeline (identity-based mode).
HttpMessageHandler resourcePipeline = BuildSigningPipeline(() => tokenHolder.Current);

if (personServer is not null)
{
    // Separate pipeline for the exchange: always signs with the agent
    // token, never the auth token, so the resource_token POST is always
    // authenticated as the agent itself.
    var exchangeHttp = new HttpClient(BuildSigningPipeline(() => agentToken));
    var metadata = new MetadataClient(new HttpClient());
    var exchange = new TokenExchangeClient(exchangeHttp, metadata);
    resourcePipeline = new ChallengeHandler(exchange, tokenHolder, personServer)
    {
        InnerHandler = resourcePipeline,
    };
}

using var client = new HttpClient(resourcePipeline);

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
