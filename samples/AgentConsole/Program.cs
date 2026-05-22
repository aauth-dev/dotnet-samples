using System;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;

const string Usage = "Usage: AgentConsole <url> [--iss <agent-provider-url>] [--sub <agent-id>] " +
    "[--kid <key-id>] [--ps <person-server-url>] [--ap <agent-provider-enrol-url>]";

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

string issuer = "https://ap.example";
string subject = "aauth:demo@ap.example";
string keyId = "demo";
string? personServer = null;
string? apUrl = null;
for (int i = 1; i < args.Length; i++)
{
    string flag = args[i];
    if (flag is "--iss" or "--sub" or "--kid" or "--ps" or "--ap")
    {
        if (i + 1 >= args.Length)
        {
            Console.Error.WriteLine($"Missing value for {flag}.");
            return 1;
        }
        var value = args[++i];
        switch (flag)
        {
            case "--iss": issuer = value; break;
            case "--sub": subject = value; break;
            case "--kid": keyId = value; break;
            case "--ps":  personServer = value; break;
            case "--ap":  apUrl = value; break;
        }
    }
    else
    {
        Console.Error.WriteLine($"Unknown argument: {flag}");
        return 1;
    }
}

var store = KeyStore.Default();
AAuthKey key;
string agentToken;

if (apUrl is not null)
{
    // Bootstrap with a real Agent Provider via AgentProviderClient
    Console.WriteLine($"Enrolling with Agent Provider at: {apUrl}");
    var apKeyStore = new InMemoryKeyStore();
    var apClient = new AgentProviderClient(new HttpClient(), apKeyStore);
    var result = await apClient.EnrolAsync(issuer, subject, apUrl);
    key = result.Key;
    agentToken = result.AgentToken;
    keyId = result.KeyId;
    Console.WriteLine($"Enrolled successfully. Key ID: {keyId}");
}
else
{
    // Local self-issued token (original behaviour)
    key = store.LoadOrCreate(keyId);
    agentToken = new AgentTokenBuilder
    {
        Issuer = issuer,
        Subject = subject,
        KeyId = keyId,
        Key = key,
        PersonServer = personServer,
    }.Build();
}

Console.WriteLine($"Using key: {keyId}");
Console.WriteLine($"Public JWK thumbprint: {key.ComputeJwkThumbprint()}");
Console.WriteLine();
Console.WriteLine("Agent token:");
Console.WriteLine(agentToken);
Console.WriteLine();

// Shared carrier-token holder. The signing handler reads from it on every
// request; the challenge handler updates it when an auth-token is issued.
var tokenHolder = new AAuthTokenHolder(agentToken);

HttpMessageHandler BuildSigningPipeline(Func<string> tokenSource) =>
    new AAuthSigningHandler(key, tokenSource)
    {
        InnerHandler = new HttpClientHandler(),
    };

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
