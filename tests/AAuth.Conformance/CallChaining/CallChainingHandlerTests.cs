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
                    ["auth_token_endpoint"] = $"{origin}/token",
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

        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);
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
                upstreamToken, TestTokens.Resource, PresentedToken,
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
                    ["auth_token_endpoint"] = $"{origin}/token",
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

        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        var upstreamToken = BuildTokenWithIss("http://localhost:7777");

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => chainHandler.ExchangeForDownstreamAsync(
            upstreamToken, TestTokens.Resource, PresentedToken,
            pollerOptions: new DeferredPollerOptions { PreferWaitSeconds = 30 }));
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
                    ["auth_token_endpoint"] = $"{origin}/token",
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

        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        var upstreamToken = BuildTokenWithIss("http://localhost:7777");

        // Call without optional params (backward compatible)
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => chainHandler.ExchangeForDownstreamAsync(
            upstreamToken, TestTokens.Resource, PresentedToken));
    }

    [Fact(DisplayName = "ExchangeForDownstreamAsync — presented_token and upstream_token are both sent")]
    public async Task ExchangeForDownstreamAsync_SendsPresentedAndUpstreamTokens()
    {
        JsonObject? body = null;
        var handler = new CapturingHandler(req =>
        {
            if (req.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = req.RequestUri.GetLeftPart(UriPartial.Authority);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(new JsonObject { ["issuer"] = origin, ["auth_token_endpoint"] = $"{origin}/token" }
                        .ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }
            body = JsonNode.Parse(req.Content!.ReadAsStringAsync().GetAwaiter().GetResult())!.AsObject();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(new JsonObject { ["auth_token"] = "token" }.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        });
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), new MetadataClient(new InProcessHttpClient(handler)));
        var chainHandler = new CallChainingHandler(exchangeClient, CreateOptions());
        var upstreamToken = BuildPersonToken("http://localhost:7777");

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() =>
            chainHandler.ExchangeForDownstreamAsync(upstreamToken, TestTokens.Resource, PresentedToken));

        Assert.Equal(PresentedToken, (string?)body!["presented_token"]);
        Assert.Equal(upstreamToken, (string?)body["upstream_token"]);
        Assert.Equal(TestTokens.Resource, (string?)body["resource_token"]);
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
                    ["auth_token_endpoint"] = $"{origin}/token",
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

        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);
        var options = CreateOptions();
        var chainHandler = new CallChainingHandler(exchangeClient, options);

        // An upstream auth token routes to its ps, not its iss.
        var upstreamToken = BuildAuthToken("http://localhost:5555", "http://localhost:8888");

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => chainHandler.ExchangeForDownstreamAsync(upstreamToken, TestTokens.Resource, PresentedToken));

        Assert.Equal("http://localhost:8888", capturedOrigin);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private const string PresentedToken = "presented.person.token";

    private static CallChainingOptions CreateOptions()
    {
        var key = AAuthKey.Generate();
        return new CallChainingOptions
        {
            AgentKey = key,
            SignatureKeyProvider = new HwkSignatureKeyProvider(key),
        };
    }

    private static string BuildTokenWithIss(string iss) => BuildPersonToken(iss);

    private static string BuildPersonToken(string iss) => BuildToken("aa-person+jwt", new JsonObject
    {
        ["iss"] = iss,
        ["aud"] = "http://localhost:6000",
        ["sub"] = "user-1",
    });

    private static string BuildAuthToken(string iss, string personServer) => BuildToken("aa-auth+jwt", new JsonObject
    {
        ["iss"] = iss,
        ["ps"] = personServer,
        ["aud"] = "http://localhost:6000",
        ["sub"] = "user-1",
    });

    private static string BuildToken(string typ, JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = "Ed25519", ["typ"] = typ, ["kid"] = "k1" };
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
