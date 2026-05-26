using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class ChallengeHandlerTests
{
    private const string PsUrl = "http://localhost:5555";
    private const string ResourceUrl = "http://localhost:6000";

    // ── Upstream token routing ──────────────────────────────────────────────

    [Fact(DisplayName = "ChallengeHandler — upstream token with mission.approver routes to approver")]
    public async Task UpstreamToken_WithMissionApprover_RoutesToApprover()
    {
        var approverUrl = "http://localhost:8888";
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = PsUrl,
            ["aud"] = ResourceUrl,
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = approverUrl },
        });

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder,
            personServer: null,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = new MockResourceHandler(),
        };

        using var client = new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await client.GetAsync("/data");

        Assert.Equal(approverUrl, capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — upstream token without mission routes to iss")]
    public async Task UpstreamToken_NoMission_RoutesToIss()
    {
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = PsUrl,
            ["aud"] = ResourceUrl,
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder,
            personServer: null,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = new MockResourceHandler(),
        };

        using var client = new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await client.GetAsync("/data");

        Assert.Equal(PsUrl, capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — no upstream token falls back to personServer")]
    public async Task NoUpstreamToken_FallsBackToPersonServer()
    {
        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder,
            personServer: PsUrl,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => null) // provider returns null
        {
            InnerHandler = new MockResourceHandler(),
        };

        using var client = new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await client.GetAsync("/data");

        Assert.Equal(PsUrl, capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — upstream token takes precedence over personServer")]
    public async Task UpstreamToken_TakesPrecedenceOverPersonServer()
    {
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "http://localhost:7777",
            ["aud"] = ResourceUrl,
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder,
            personServer: PsUrl, // should be ignored
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = new MockResourceHandler(),
        };

        using var client = new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await client.GetAsync("/data");

        Assert.Equal("http://localhost:7777", capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — throws when both personServer and upstreamTokenProvider are null")]
    public void ThrowsWhenBothNull()
    {
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);
        var holder = new AAuthTokenHolder("token");

        Assert.Throws<ArgumentException>(() => new ChallengeHandler(
            exchangeClient, holder,
            personServer: null,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: null));
    }

    [Fact(DisplayName = "ChallengeHandler — backward-compatible constructor still works")]
    public async Task BackwardCompatibleConstructor_Works()
    {
        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        // Use original constructor signature (non-nullable personServer)
        var challengeHandler = new ChallengeHandler(exchangeClient, holder, PsUrl)
        {
            InnerHandler = new MockResourceHandler(),
        };

        using var client = new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await client.GetAsync("/data");

        Assert.Equal(PsUrl, capturedTokenEndpoint);
    }

    // ── Prefer header on initial exchange ───────────────────────────────────

    [Fact(DisplayName = "TokenExchangeClient — initial POST includes Prefer: wait=N when configured")]
    public async Task InitialExchangePost_IncludesPreferHeader()
    {
        string? capturedPrefer = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            if (req.Headers.TryGetValues("Prefer", out var values))
                capturedPrefer = string.Join(",", values);
        });

        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        await exchangeClient.ExchangeAsync(
            PsUrl, "fake-resource-token",
            onInteractionRequired: null,
            pollerOptions: new DeferredPollerOptions { PreferWaitSeconds = 45 },
            upstreamToken: null);

        Assert.Equal("wait=45", capturedPrefer);
    }

    [Fact(DisplayName = "TokenExchangeClient — initial POST omits Prefer when not configured")]
    public async Task InitialExchangePost_OmitsPreferWhenNotConfigured()
    {
        string? capturedPrefer = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            if (req.Headers.TryGetValues("Prefer", out var values))
                capturedPrefer = string.Join(",", values);
        });

        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        await exchangeClient.ExchangeAsync(
            PsUrl, "fake-resource-token",
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamToken: null);

        Assert.Null(capturedPrefer);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string BuildTokenWithPayload(JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = "k1" };
        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return $"{h}.{p}.fake-sig";
    }

    /// <summary>Returns a 401 challenge on first request, then 200 on retry.</summary>
    private sealed class MockResourceHandler : HttpMessageHandler
    {
        private int _callCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var call = Interlocked.Increment(ref _callCount);
            if (call == 1)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Headers.TryAddWithoutValidation(
                    AAuthRequirementHeader.Name,
                    AAuthRequirementHeader.FormatAuthToken("fake-resource-token"));
                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}"),
            });
        }
    }

    /// <summary>
    /// Handler that serves metadata for any well-known request and captures
    /// token endpoint POST requests for assertion.
    /// </summary>
    private sealed class CapturingExchangeHandler : HttpMessageHandler
    {
        private readonly Action<HttpRequestMessage> _onTokenPost;
        public CapturingExchangeHandler(Action<HttpRequestMessage> onTokenPost) => _onTokenPost = onTokenPost;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            // Metadata discovery — return token_endpoint at the same origin
            if (request.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = request.RequestUri.GetLeftPart(UriPartial.Authority);
                var metadata = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }

            // Token endpoint POST — capture and return auth_token
            _onTokenPost(request);
            var response = new JsonObject { ["auth_token"] = "fake-auth-token" };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"),
            });
        }
    }
}
