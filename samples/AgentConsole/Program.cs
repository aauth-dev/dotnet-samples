using System;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: AgentConsole <url> [--iss <agent-provider-url>] [--sub <agent-id>] [--kid <key-id>]");
    return 1;
}

var url = new Uri(args[0]);

string issuer = "https://ap.example";
string subject = "aauth:demo@ap.example";
string keyId = "demo";
for (int i = 1; i < args.Length - 1; i++)
{
    switch (args[i])
    {
        case "--iss": issuer = args[++i]; break;
        case "--sub": subject = args[++i]; break;
        case "--kid": keyId = args[++i]; break;
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
