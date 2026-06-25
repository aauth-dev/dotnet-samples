using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.HttpSig;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class ChallengeHandlerTests
{
    private const string PsUrl = "http://localhost:5555";
    private const string ResourceUrl = "http://localhost:6000";
    private static readonly HttpRequestOptionsKey<string> CustomOptionKey = new("Test.CallerState");

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
            ["act"] = new JsonObject { ["agent"] = "agent-1" },
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
            ["act"] = new JsonObject { ["agent"] = "agent-1" },
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
            ["act"] = new JsonObject { ["agent"] = "agent-1" },
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
            new TokenExchangeRequest
            {
                PollerOptions = new DeferredPollerOptions { PreferWaitSeconds = 45 },
            });

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
            new TokenExchangeRequest());

        Assert.Null(capturedPrefer);
    }

    // ── Capabilities & prompt in exchange body ──────────────────────────────

    [Fact(DisplayName = "TokenExchangeClient — infers 'interaction' capability when callback supplied")]
    public async Task ExchangeBody_InfersInteractionCapability()
    {
        var body = await CaptureExchangeBodyAsync(
            onInteractionRequired: (_, _) => Task.CompletedTask);

        var caps = body!["capabilities"]!.AsArray();
        Assert.Single(caps);
        Assert.Equal("interaction", (string)caps[0]!);
    }

    [Fact(DisplayName = "TokenExchangeClient — omits capabilities when no callback and none specified")]
    public async Task ExchangeBody_OmitsCapabilities_WhenNoCallback()
    {
        var body = await CaptureExchangeBodyAsync(onInteractionRequired: null);

        Assert.False(body!.ContainsKey("capabilities"));
    }

    [Fact(DisplayName = "TokenExchangeClient — explicit capabilities override inference")]
    public async Task ExchangeBody_ExplicitCapabilities_Override()
    {
        var body = await CaptureExchangeBodyAsync(
            onInteractionRequired: (_, _) => Task.CompletedTask,
            capabilities: new[] { "interaction", "payment" });

        var caps = body!["capabilities"]!.AsArray();
        Assert.Equal(2, caps.Count);
        Assert.Equal("interaction", (string)caps[0]!);
        Assert.Equal("payment", (string)caps[1]!);
    }

    [Fact(DisplayName = "TokenExchangeClient — empty capabilities list suppresses the field")]
    public async Task ExchangeBody_EmptyCapabilities_Suppresses()
    {
        var body = await CaptureExchangeBodyAsync(
            onInteractionRequired: (_, _) => Task.CompletedTask,
            capabilities: Array.Empty<string>());

        Assert.False(body!.ContainsKey("capabilities"));
    }

    [Fact(DisplayName = "TokenExchangeClient — sends prompt when supplied")]
    public async Task ExchangeBody_SendsPrompt_WhenSupplied()
    {
        var body = await CaptureExchangeBodyAsync(
            onInteractionRequired: null, prompt: "consent");

        Assert.Equal("consent", (string)body!["prompt"]!);
    }

    [Fact(DisplayName = "TokenExchangeClient — omits prompt when not supplied")]
    public async Task ExchangeBody_OmitsPrompt_WhenNotSupplied()
    {
        var body = await CaptureExchangeBodyAsync(onInteractionRequired: null);

        Assert.False(body!.ContainsKey("prompt"));
    }

    // ── Typed token-exchange errors (Gap E) ─────────────────────────────────

    [Theory(DisplayName = "TokenExchangeClient — non-2xx with error body throws typed exception")]
    [InlineData(HttpStatusCode.BadRequest, "invalid_resource_token", true)]
    [InlineData(HttpStatusCode.BadRequest, "expired_agent_token", true)]
    [InlineData(HttpStatusCode.Forbidden, "user_unreachable", true)]
    [InlineData(HttpStatusCode.Forbidden, "interaction_required", true)]
    [InlineData(HttpStatusCode.InternalServerError, "server_error", false)]
    public async Task Exchange_NonSuccessWithErrorBody_ThrowsTyped(
        HttpStatusCode status, string errorCode, bool expectedTerminal)
    {
        var exchangeHandler = new ErrorExchangeHandler(status,
            $"{{\"error\":\"{errorCode}\",\"error_description\":\"boom\"}}");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        var ex = await Assert.ThrowsAsync<AAuth.Errors.AAuthTokenExchangeException>(
            () => exchangeClient.ExchangeAsync(PsUrl, "fake-resource-token"));

        Assert.Equal(errorCode, ex.ErrorCode);
        Assert.Equal("boom", ex.ErrorDescription);
        Assert.Equal((int)status, ex.StatusCode);
        Assert.Equal(expectedTerminal, ex.IsTerminal);
    }

    [Fact(DisplayName = "TokenExchangeClient — non-2xx without parseable error falls back to HttpRequestException")]
    public async Task Exchange_NonSuccessWithoutErrorBody_FallsBack()
    {
        var exchangeHandler = new ErrorExchangeHandler(
            HttpStatusCode.BadGateway, "<html>nginx 502</html>");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => exchangeClient.ExchangeAsync(PsUrl, "fake-resource-token"));
    }

    [Fact(DisplayName = "TokenExchangeClient — JSON body without 'error' member falls back to HttpRequestException")]
    public async Task Exchange_JsonWithoutError_FallsBack()
    {
        var exchangeHandler = new ErrorExchangeHandler(
            HttpStatusCode.BadRequest, "{\"detail\":\"something\"}");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => exchangeClient.ExchangeAsync(PsUrl, "fake-resource-token"));
    }

    private static async Task<JsonObject?> CaptureExchangeBodyAsync(
        Func<Interaction, CancellationToken, Task>? onInteractionRequired,
        IReadOnlyList<string>? capabilities = null,
        string? prompt = null)
    {
        JsonObject? capturedBody = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            if (req.Content is not null)
            {
                var json = req.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                capturedBody = JsonNode.Parse(json) as JsonObject;
            }
        });

        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        await exchangeClient.ExchangeAsync(
            PsUrl, "fake-resource-token",
            new TokenExchangeRequest
            {
                OnInteractionRequired = onInteractionRequired,
                Capabilities = capabilities,
                Prompt = prompt,
            });

        return capturedBody;
    }

    // ── Adaptive signing components (§Covered Components) ───────────────────

    [Fact(DisplayName = "ChallengeHandler — invalid_input learns required components and retries once")]
    public async Task AdaptiveSigning_InvalidInput_LearnsAndRetriesOnce()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-digest"),
            _ => Ok());

        using var client = BuildAdaptiveClient(resource, out _);
        var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, resource.CallCount);
        // First attempt has no extra components; the retry carries the learned set.
        Assert.Null(resource.Observed[0]);
        Assert.NotNull(resource.Observed[1]);
        Assert.Equal(new[] { "content-digest" }, resource.Observed[1]!);
    }

    [Fact(DisplayName = "ChallengeHandler — learned components are cached per origin for later requests")]
    public async Task AdaptiveSigning_LearnedComponents_CachedForLaterRequests()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-digest"),
            _ => Ok(),
            _ => Ok());

        using var client = BuildAdaptiveClient(resource, out _);
        await client.GetAsync("/data");   // attempt 1 (401) + retry (200)
        await client.GetAsync("/more");   // attempt 3 should be proactively seeded

        Assert.Equal(3, resource.CallCount);
        Assert.Equal(new[] { "content-digest" }, resource.Observed[2]!);
    }

    [Fact(DisplayName = "ChallengeHandler — metadata-seeded components cover the first request")]
    public async Task AdaptiveSigning_MetadataSeed_CoversFirstRequest()
    {
        var resource = new AdaptiveResourceHandler(_ => Ok());
        var seed = new Dictionary<string, IReadOnlyList<string>>
        {
            [ResourceUrl] = new[] { "content-type" },
        };

        using var client = BuildAdaptiveClient(resource, out _, seed);
        await client.GetAsync("/data");

        Assert.Equal(1, resource.CallCount);
        Assert.Equal(new[] { "content-type" }, resource.Observed[0]!);
    }

    [Fact(DisplayName = "ChallengeHandler — invalid_input merges learned components on top of metadata seed")]
    public async Task AdaptiveSigning_InvalidInput_MergesOnTopOfMetadataSeed()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-digest"),
            _ => Ok());
        var seed = new Dictionary<string, IReadOnlyList<string>>
        {
            [ResourceUrl] = new[] { "content-type" },
        };

        using var client = BuildAdaptiveClient(resource, out _, seed);
        await client.GetAsync("/data");

        Assert.Equal(2, resource.CallCount);
        Assert.Equal(new[] { "content-type" }, resource.Observed[0]!);
        Assert.Equal(new[] { "content-type", "content-digest" }, resource.Observed[1]!);
    }

    [Fact(DisplayName = "ChallengeHandler — no Signature-Error returns response unchanged")]
    public async Task AdaptiveSigning_NoSignatureError_NoRetry()
    {
        var resource = new AdaptiveResourceHandler(_ => Ok());

        using var client = BuildAdaptiveClient(resource, out _);
        var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, resource.CallCount);
        Assert.Null(resource.Observed[0]);
    }

    [Fact(DisplayName = "ChallengeHandler — invalid_input without required_input does not retry")]
    public async Task AdaptiveSigning_InvalidInputWithoutRequiredInput_NoRetry()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput(/* no required_input */));

        using var client = BuildAdaptiveClient(resource, out _);
        var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, resource.CallCount);
    }

    [Fact(DisplayName = "ChallengeHandler — seed merges caller-set components additively")]
    public async Task AdaptiveSigning_Seed_MergesCallerSetComponents()
    {
        var resource = new AdaptiveResourceHandler(_ => Ok());
        var seed = new Dictionary<string, IReadOnlyList<string>>
        {
            [ResourceUrl] = new[] { "content-type" },
        };

        using var client = BuildAdaptiveClient(resource, out _, seed);

        var request = new HttpRequestMessage(HttpMethod.Get, "/data");
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey, new[] { "x-caller" });
        await client.SendAsync(request);

        Assert.Equal(1, resource.CallCount);
        // Caller-set component is preserved additively alongside the seed.
        Assert.Equal(new[] { "content-type", "x-caller" }, resource.Observed[0]!);
    }

    [Fact(DisplayName = "ChallengeHandler — non-AAuth request option survives the adaptive retry clone")]
    public async Task AdaptiveSigning_CloneAsync_PreservesCallerOption()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-type"),
            _ => Ok());

        using var client = BuildAdaptiveClient(resource, out _);

        var request = new HttpRequestMessage(HttpMethod.Get, "/data");
        request.Options.Set(CustomOptionKey, "caller-state");
        await client.SendAsync(request);

        Assert.Equal(2, resource.CallCount);
        // Both the first attempt and the retried clone carry the caller option.
        Assert.Equal("caller-state", resource.ObservedCustom[0]);
        Assert.Equal("caller-state", resource.ObservedCustom[1]);
    }

    [Fact(DisplayName = "ChallengeHandler — adaptive retry happens at most once")]
    public async Task AdaptiveSigning_RetriesAtMostOnce()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-digest"),
            _ => InvalidInput("content-digest"));

        using var client = BuildAdaptiveClient(resource, out _);
        var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(2, resource.CallCount);
    }

    [Fact(DisplayName = "ChallengeHandler — learned components persist for later requests to the same origin")]
    public async Task AdaptiveSigning_LearnedComponents_PersistAcrossRequests()
    {
        var resource = new AdaptiveResourceHandler(
            _ => InvalidInput("content-digest"), // request 1, attempt 1
            _ => Ok(),                            // request 1, retry (learns content-digest)
            _ => Ok());                           // request 2, first attempt

        using var client = BuildAdaptiveClient(resource, out _);

        await client.GetAsync("/data");
        await client.GetAsync("/data");

        Assert.Equal(3, resource.CallCount);
        Assert.Null(resource.Observed[0]);
        Assert.Equal(new[] { "content-digest" }, resource.Observed[1]!);
        // Second request signs content-digest up front from the learned set.
        Assert.Equal(new[] { "content-digest" }, resource.Observed[2]!);
    }

    private static HttpClient BuildAdaptiveClient(
        HttpMessageHandler resource,
        out AAuthTokenHolder holder,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? seed = null)
    {
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);
        holder = new AAuthTokenHolder("initial-token");

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, personServer: PsUrl)
        {
            InnerHandler = resource,
            AdditionalSignatureComponents = seed,
        };

        return new HttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
    }

    private static HttpResponseMessage InvalidInput(params string[] required)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.TryAddWithoutValidation(
            SignatureError.HeaderName,
            SignatureError.Format(SignatureErrorCode.InvalidInput, required));
        return response;
    }

    private static HttpResponseMessage Ok()
        => new(HttpStatusCode.OK) { Content = new StringContent("{\"ok\":true}") };

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string BuildTokenWithPayload(JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = "k1" };
        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return $"{h}.{p}.fake-sig";
    }

    /// <summary>
    /// Resource handler driven by a per-call script. Records the additional
    /// signature components observed in each request's options so adaptive
    /// signing behaviour can be asserted.
    /// </summary>
    private sealed class AdaptiveResourceHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _script;
        public System.Collections.Generic.List<IReadOnlyList<string>?> Observed { get; } = new();
        public System.Collections.Generic.List<string?> ObservedCustom { get; } = new();
        public int CallCount { get; private set; }

        public AdaptiveResourceHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] script)
            => _script = new Queue<Func<HttpRequestMessage, HttpResponseMessage>>(script);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            request.Options.TryGetValue(AAuthSigningHandler.AdditionalComponentsKey, out var comps);
            Observed.Add(comps);
            ObservedCustom.Add(
                request.Options.TryGetValue(CustomOptionKey, out var custom) ? custom : null);
            var step = _script.Count > 0
                ? _script.Dequeue()
                : (_ => new HttpResponseMessage(HttpStatusCode.OK));
            return Task.FromResult(step(request));
        }
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

    /// <summary>
    /// Serves metadata for well-known requests and returns a fixed
    /// non-success status + body for the token endpoint POST.
    /// </summary>
    private sealed class ErrorExchangeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;
        public ErrorExchangeHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
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

            return Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            });
        }
    }
}
