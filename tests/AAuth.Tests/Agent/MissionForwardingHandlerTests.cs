using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class MissionForwardingHandlerTests
{
    private static string CreateToken(JsonObject? payload = null)
    {
        var header = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt" };
        payload ??= new JsonObject { ["iss"] = "https://ps.example", ["sub"] = "user1" };
        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return $"{headerB64}.{payloadB64}.fakesignature";
    }

    private static string CreateTokenWithMission(string approver = "https://ps.example", string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    {
        var payload = new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["sub"] = "user1",
            ["mission"] = new JsonObject
            {
                ["approver"] = approver,
                ["s256"] = s256,
            },
        };
        return CreateToken(payload);
    }

    [Fact]
    public async Task Emits_mission_header_when_upstream_has_mission()
    {
        var token = CreateTokenWithMission();
        var capturedHeaders = new List<string>();

        var inner = new CapturingHandler(capturedHeaders);
        var handler = new MissionForwardingHandler(() => token)
        {
            InnerHandler = inner,
        };

        using var client = new HttpClient(handler);
        await client.GetAsync("https://downstream.example/resource");

        Assert.Single(capturedHeaders);
        Assert.Contains("approver=\"https://ps.example\"", capturedHeaders[0]);
        Assert.Contains("s256=\"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"", capturedHeaders[0]);
    }

    [Fact]
    public async Task No_header_when_upstream_has_no_mission()
    {
        var token = CreateToken();
        var capturedHeaders = new List<string>();

        var inner = new CapturingHandler(capturedHeaders);
        var handler = new MissionForwardingHandler(() => token)
        {
            InnerHandler = inner,
        };

        using var client = new HttpClient(handler);
        await client.GetAsync("https://downstream.example/resource");

        Assert.Empty(capturedHeaders);
    }

    [Fact]
    public async Task No_header_when_upstream_token_is_null()
    {
        var capturedHeaders = new List<string>();

        var inner = new CapturingHandler(capturedHeaders);
        var handler = new MissionForwardingHandler(() => null)
        {
            InnerHandler = inner,
        };

        using var client = new HttpClient(handler);
        await client.GetAsync("https://downstream.example/resource");

        Assert.Empty(capturedHeaders);
    }

    [Fact]
    public async Task No_header_when_mission_approver_is_empty()
    {
        var payload = new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["sub"] = "user1",
            ["mission"] = new JsonObject
            {
                ["approver"] = "",
                ["s256"] = "abc123",
            },
        };
        var token = CreateToken(payload);
        var capturedHeaders = new List<string>();

        var inner = new CapturingHandler(capturedHeaders);
        var handler = new MissionForwardingHandler(() => token)
        {
            InnerHandler = inner,
        };

        using var client = new HttpClient(handler);
        await client.GetAsync("https://downstream.example/resource");

        Assert.Empty(capturedHeaders);
    }

    [Fact]
    public async Task No_header_when_mission_s256_is_missing()
    {
        var payload = new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["sub"] = "user1",
            ["mission"] = new JsonObject
            {
                ["approver"] = "https://ps.example",
            },
        };
        var token = CreateToken(payload);
        var capturedHeaders = new List<string>();

        var inner = new CapturingHandler(capturedHeaders);
        var handler = new MissionForwardingHandler(() => token)
        {
            InnerHandler = inner,
        };

        using var client = new HttpClient(handler);
        await client.GetAsync("https://downstream.example/resource");

        Assert.Empty(capturedHeaders);
    }

    [Fact]
    public void FormatStructured_produces_spec_correct_header()
    {
        var result = AAuthMissionHeader.FormatStructured(
            "https://ps.example",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.Equal(
            "approver=\"https://ps.example\"; s256=\"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"",
            result);
    }

    [Fact]
    public void FormatStructured_throws_on_empty_approver()
    {
        Assert.Throws<ArgumentException>(() =>
            AAuthMissionHeader.FormatStructured("", "abc"));
    }

    [Fact]
    public void FormatStructured_throws_on_empty_s256()
    {
        Assert.Throws<ArgumentException>(() =>
            AAuthMissionHeader.FormatStructured("https://ps.example", ""));
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly List<string> _capturedMissionHeaders;

        public CapturingHandler(List<string> capturedMissionHeaders)
        {
            _capturedMissionHeaders = capturedMissionHeaders;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.TryGetValues(AAuthMissionHeader.Name, out var values))
            {
                foreach (var v in values)
                    _capturedMissionHeaders.Add(v);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
