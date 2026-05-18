using System;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;

const string Usage = "Usage: AgentConsole <url> [--iss <agent-provider-url>] [--sub <agent-id>] [--kid <key-id>]";

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
for (int i = 1; i < args.Length; i++)
{
    string flag = args[i];
    if (flag is "--iss" or "--sub" or "--kid")
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
        }
    }
    else
    {
        Console.Error.WriteLine($"Unknown argument: {flag}");
        return 1;
    }
}

var store = KeyStore.Default();
var key = store.LoadOrCreate(keyId);

Console.WriteLine($"Using key: {keyId}");
Console.WriteLine($"Public JWK thumbprint: {key.ComputeJwkThumbprint()}");

var token = new AgentTokenBuilder
{
    Issuer = issuer,
    Subject = subject,
    KeyId = keyId,
    Key = key,
}.Build();

Console.WriteLine();
Console.WriteLine("Agent token:");
Console.WriteLine(token);
Console.WriteLine();

var handler = new AAuthSigningHandler(key, () => token)
{
    InnerHandler = new HttpClientHandler(),
};
using var client = new HttpClient(handler);

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
