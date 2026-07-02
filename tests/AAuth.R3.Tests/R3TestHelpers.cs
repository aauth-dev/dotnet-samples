using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.R3;
using AAuth.R3.Model;
using AAuth.Tokens;

namespace AAuth.R3.Tests;

internal static class R3TestData
{
    public const string AsIssuer = "https://as.test";
    public const string PsIssuer = "https://ps.test";
    public const string ApIssuer = "https://ap.test";
    public const string ResourceIssuer = "https://resource.test";
    public const string AgentId = "aauth:demo@ap.test";

    public const string AsKid = "as-1";
    public const string PsKid = "ps-1";
    public const string ApKid = "ap-1";
    public const string ResourceKid = "resource-1";

    public static JsonObject Metadata(string issuer, string dwk) => new()
    {
        ["issuer"] = issuer,
        ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
        ["token_endpoint"] = $"{issuer}/token",
    };

    public static JsonObject Jwks(string kid, AAuthKey key)
    {
        var jwk = key.ToPublicJwk();
        jwk["kid"] = kid;
        jwk["use"] = "sig";
        jwk["alg"] = AAuthKey.Algorithm;
        return new JsonObject { ["keys"] = new JsonArray(jwk) };
    }

    public static string AgentToken(AAuthKey apKey, AAuthKey agentKey) => new AgentTokenBuilder
    {
        Issuer = ApIssuer,
        Subject = AgentId,
        Key = apKey,
        ConfirmationKey = agentKey,
        KeyId = ApKid,
    }.Build();

    public static string ResourceToken(AAuthKey resourceKey, AAuthKey agentKey, string r3Uri, string r3S256) =>
        new R3Challenge
        {
            ResourceIssuer = ResourceIssuer,
            Audience = AsIssuer,
            Key = resourceKey,
            KeyId = ResourceKid,
            Clock = () => DateTimeOffset.UtcNow,
        }.BuildResourceToken(AgentId, agentKey.ComputeJwkThumbprint(), r3Uri, r3S256);

    public static R3Document Document() => new()
    {
        Version = "v02",
        Vocabulary = Vocabulary.Mcp,
        Operations =
        [
            new McpOperation { Tool = "search_trip_options" },
            new McpOperation { Tool = "hold_itinerary" },
            new McpOperation { Tool = "book_trip" },
        ],
        Display = new R3Display
        {
            Summary = "Search and hold trip options; booking may charge payment.",
            Irreversible = "Booking a trip may charge the payment method on file.",
        },
        Conditional = [new McpOperation { Tool = "book_trip" }],
    };
}

internal sealed class StaticJsonHandler : HttpMessageHandler
{
    private readonly Dictionary<string, JsonObject> _json = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _bytes = new(StringComparer.Ordinal);

    public StaticJsonHandler AddJson(string url, JsonObject json)
    {
        _json[url] = json;
        return this;
    }

    public StaticJsonHandler AddBytes(string url, byte[] bytes)
    {
        _bytes[url] = bytes;
        return this;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        if (_json.TryGetValue(url, out var json))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json"),
            });
        }
        if (_bytes.TryGetValue(url, out var bytes))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes) { Headers = { ContentType = new("application/json") } },
            });
        }
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent($"No fixture for {url}"),
        });
    }
}
