using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.CallChaining;

/// <summary>
/// Conformance tests for <see cref="CallChainingHandler"/> verifying the
/// updated <c>ExchangeForDownstreamAsync</c> signature accepts interaction
/// and poller callbacks.
/// </summary>
public class CallChainingHandlerTests
{
    [Fact(DisplayName = "ExchangeForDownstreamAsync — passes onInteractionRequired to exchange")]
    public async Task ExchangeForDownstreamAsync_PassesInteractionCallback()
    {
        bool callbackInvoked = false;
        var handler = new CapturingHandler(req =>
        {
            if (req.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = req.RequestUri.GetLeftPart(UriPartial.Authority);
                var meta = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(meta.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            // Return 202 with interaction requirement to trigger callback
            var resp = new HttpResponseMessage(HttpStatusCode.Accepted);
            resp.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name,
                "requirement=interaction; url=\"https://ps.example/interact/123\"; code=\"ABC123\"");
            resp.Headers.Location = new Uri($"{req.RequestUri!.GetLeftPart(UriPartial.Authority)}/token/poll");
            return resp;
        });

        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        var upstreamToken = BuildTokenWithIss("http://localhost:7777");

        // The exchange will get 202 → invoke callback → then poll
        // Since our mock always returns 202, it will eventually time out.
        // We just need to verify the callback IS invoked.
        var pollerOptions = new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromMilliseconds(100),
            DefaultPollInterval = TimeSpan.FromMilliseconds(50),
        };

        try
        {
            await chainHandler.ExchangeForDownstreamAsync(
                upstreamToken, "resource-token",
                onInteractionRequired: (interaction, ct) =>
                {
                    callbackInvoked = true;
                    Assert.Equal("https://ps.example/interact/123", interaction.Url);
                    Assert.Equal("ABC123", interaction.Code);
                    return Task.CompletedTask;
                },
                pollerOptions: pollerOptions);
        }
        catch (AAuthInteractionTimeoutException)
        {
            // Expected — mock never returns auth_token
        }

        Assert.True(callbackInvoked);
    }

    [Fact(DisplayName = "ExchangeForDownstreamAsync — passes pollerOptions (PreferWaitSeconds)")]
    public async Task ExchangeForDownstreamAsync_PassesPollerOptions()
    {
        string? capturedPrefer = null;
        var handler = new CapturingHandler(req =>
        {
            if (req.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = req.RequestUri.GetLeftPart(UriPartial.Authority);
                var meta = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(meta.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            if (req.Headers.TryGetValues("Prefer", out var values))
                capturedPrefer = string.Join(",", values);

            var tokenResp = new JsonObject { ["auth_token"] = "chained-auth-token" };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(tokenResp.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        });

        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        var upstreamToken = BuildTokenWithIss("http://localhost:7777");

        var result = await chainHandler.ExchangeForDownstreamAsync(
            upstreamToken, "resource-token",
            pollerOptions: new DeferredPollerOptions { PreferWaitSeconds = 30 });

        Assert.Equal("chained-auth-token", result);
        Assert.Equal("wait=30", capturedPrefer);
    }

    [Fact(DisplayName = "ExchangeForDownstreamAsync — null callbacks work (backward compatible)")]
    public async Task ExchangeForDownstreamAsync_NullCallbacks_BackwardCompatible()
    {
        var handler = new CapturingHandler(req =>
        {
            if (req.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = req.RequestUri.GetLeftPart(UriPartial.Authority);
                var meta = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(meta.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            var tokenResp = new JsonObject { ["auth_token"] = "chained-token" };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(tokenResp.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        });

        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        var upstreamToken = BuildTokenWithIss("http://localhost:7777");

        // Call without optional params (backward compatible)
        var result = await chainHandler.ExchangeForDownstreamAsync(
            upstreamToken, "resource-token");

        Assert.Equal("chained-token", result);
    }

    [Fact(DisplayName = "ExchangeForDownstreamAsync — delegates routing to CallChainingRouter")]
    public async Task ExchangeForDownstreamAsync_DelegatesRoutingToRouter()
    {
        string? capturedOrigin = null;
        var handler = new CapturingHandler(req =>
        {
            if (req.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = req.RequestUri.GetLeftPart(UriPartial.Authority);
                var meta = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(meta.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            capturedOrigin = req.RequestUri?.GetLeftPart(UriPartial.Authority);
            var tokenResp = new JsonObject { ["auth_token"] = "token" };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(tokenResp.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        });

        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        // Token with mission.approver → should route to approver
        var upstreamToken = BuildTokenWithMissionApprover("http://localhost:8888");

        await chainHandler.ExchangeForDownstreamAsync(upstreamToken, "resource-token");

        Assert.Equal("http://localhost:8888", capturedOrigin);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static CallChainingOptions CreateOptions()
    {
        var key = AAuthKey.Generate();
        return new CallChainingOptions
        {
            AgentKey = key,
            SignatureKeyProvider = new HwkSignatureKeyProvider(key),
        };
    }

    private static string BuildTokenWithIss(string iss)
    {
        var payload = new JsonObject
        {
            ["iss"] = iss,
            ["aud"] = "http://localhost:6000",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["agent"] = "agent-1" },
        };
        return BuildToken(payload);
    }

    private static string BuildTokenWithMissionApprover(string approver)
    {
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["aud"] = "http://localhost:6000",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["agent"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = approver },
        };
        return BuildToken(payload);
    }

    private static string BuildToken(JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = "k1" };
        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return $"{h}.{p}.fake-sig";
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) => _handler = handler;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(_handler(request));
    }
}
