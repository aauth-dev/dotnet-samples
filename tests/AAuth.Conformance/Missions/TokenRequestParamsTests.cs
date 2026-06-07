using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the optional agent token-request parameters (AAuth protocol
/// §Agent Token Request): <c>justification</c>, <c>login_hint</c>, <c>tenant</c>,
/// <c>domain_hint</c>, <c>platform</c>, and <c>device</c>.
/// </summary>
public class TokenRequestParamsTests
{
    private const string Ps = "http://localhost:5555";

    private static TokenExchangeClient BuildClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri(Ps) };
        var metadata = new MetadataClient(new HttpClient(handler));
        return new TokenExchangeClient(http, metadata);
    }

    [Fact(DisplayName = "§Agent Token Request — all optional params are serialized into the POST body")]
    public async Task OptionalParams_SerializedIntoBody()
    {
        JsonObject? captured = null;
        var client = BuildClient(new CaptureHandler(body => captured = body));

        await client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
        {
            Justification = "Booking a flight on your behalf.",
            LoginHint = "alice@example.com",
            Tenant = "contoso",
            DomainHint = "example.com",
            Platform = "ios",
            Device = "iphone-15",
        });

        Assert.NotNull(captured);
        Assert.Equal("Booking a flight on your behalf.", (string?)captured!["justification"]);
        Assert.Equal("alice@example.com", (string?)captured["login_hint"]);
        Assert.Equal("contoso", (string?)captured["tenant"]);
        Assert.Equal("example.com", (string?)captured["domain_hint"]);
        Assert.Equal("ios", (string?)captured["platform"]);
        Assert.Equal("iphone-15", (string?)captured["device"]);
    }

    [Fact(DisplayName = "§Agent Token Request — unset optional params are omitted from the POST body")]
    public async Task OptionalParams_OmittedWhenUnset()
    {
        JsonObject? captured = null;
        var client = BuildClient(new CaptureHandler(body => captured = body));

        await client.ExchangeAsync(Ps, "fake-resource-token");

        Assert.NotNull(captured);
        Assert.False(captured!.ContainsKey("justification"));
        Assert.False(captured.ContainsKey("login_hint"));
        Assert.False(captured.ContainsKey("tenant"));
        Assert.False(captured.ContainsKey("domain_hint"));
        Assert.False(captured.ContainsKey("platform"));
        Assert.False(captured.ContainsKey("device"));
    }

    [Fact(DisplayName = "§Agent Token Request — device is accepted at the 64-char boundary")]
    public void Device_AtMaxLength_Accepted()
    {
        var device = new string('a', 64);
        var request = new TokenExchangeRequest { Device = device };
        Assert.Equal(device, request.Device);
    }

    [Fact(DisplayName = "§Agent Token Request — device longer than 64 chars is rejected")]
    public void Device_TooLong_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new TokenExchangeRequest { Device = new string('a', 65) });
        Assert.Equal("Device", ex.ParamName);
    }

    [Theory(DisplayName = "§Agent Token Request — device with control characters is rejected")]
    [InlineData("Chrome on\tmacOS")]
    [InlineData("line\nbreak")]
    [InlineData("null\0byte")]
    [InlineData("bell\u0007")]
    public void Device_ControlCharacters_Throws(string device)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new TokenExchangeRequest { Device = device });
        Assert.Equal("Device", ex.ParamName);
    }

    [Fact(DisplayName = "§Agent Token Request — printable device string is accepted")]
    public void Device_Printable_Accepted()
    {
        var request = new TokenExchangeRequest { Device = "Chrome on macOS (M3)" };
        Assert.Equal("Chrome on macOS (M3)", request.Device);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly Action<JsonObject> _onBody;
        public CaptureHandler(Action<JsonObject> onBody) => _onBody = onBody;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath == "/.well-known/aauth-person.json")
            {
                return Json(new JsonObject
                {
                    ["issuer"] = Ps,
                    ["token_endpoint"] = Ps + "/token",
                });
            }

            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
            _onBody(body);
            return Json(new JsonObject { ["auth_token"] = "fake-auth-token" });
        }

        private static HttpResponseMessage Json(JsonObject body)
            => new(HttpStatusCode.OK)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
