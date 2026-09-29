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
using AAuth.Tokens;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class ChallengeHandlerTests
{
    private const string PsUrl = "http://localhost:5555";
    private const string ResourceUrl = "http://localhost:6000";
    private static readonly AAuthKey SigningKey = AAuthKey.Generate();
    private static readonly string AgentToken = new AgentTokenBuilder
    {
        Issuer = "https://ap.example", Subject = "aauth:test@ap.example", Key = SigningKey,
        KeyId = "agent-key", ConfirmationKey = SigningKey,
    }.Build();
    private static string ResourceToken => BuildResourceToken();
    private const string PersonSubject = "person-1";
    private const string PersonJti = "person-jti-1";
    private static readonly string MissionHash = Base64UrlEncoder.Encode(new byte[32]);
    private static readonly HttpRequestOptionsKey<string> CustomOptionKey = new("Test.CallerState");

    // ── Upstream token routing ──────────────────────────────────────────────

    [Fact(DisplayName = "ChallengeHandler — upstream auth token routes to its ps, not its iss")]
    public async Task UpstreamToken_RoutesToItsPersonServer()
    {
        var personServerUrl = "http://localhost:8888";
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "http://localhost:7777",
            ["ps"] = personServerUrl,
            ["aud"] = ResourceUrl,
            ["sub"] = "upstream-person",
        });

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: null,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = SignedResource(BuildResourceToken(personServer: personServerUrl)),
        };

        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

        Assert.Equal(personServerUrl, capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — upstream token naming this ps routes to it")]
    public async Task UpstreamToken_NoMission_RoutesToIss()
    {
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = PsUrl,
            ["ps"] = PsUrl,
            ["aud"] = ResourceUrl,
            ["sub"] = "upstream-person",
        });

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: null,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = SignedResource(),
        };

        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

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
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: PsUrl,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => null) // provider returns null
        {
            InnerHandler = SignedResource(),
        };

        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

        Assert.Equal(PsUrl, capturedTokenEndpoint);
    }

    [Theory(DisplayName = "ChallengeHandler — a matching mission person token is reused instead of calling /person; a mismatch falls back")]
    [InlineData("match")]
    [InlineData("resource")]
    [InlineData("mission")]
    [InlineData("key")]
    [InlineData("expiry")]
    public async Task MissionPersonToken_ReusedOnlyWhenItMatches(string variant)
    {
        var mission = Base64UrlEncoder.Encode(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("mission")));
        var token = new PersonTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = PsUrl, Audience = ResourceUrl, Subject = PersonSubject,
            ConfirmationKey = variant == "key" ? AAuthKey.Generate() : SigningKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.Add(variant == "expiry" ? TimeSpan.FromSeconds(30) : TimeSpan.FromHours(1)),
            Key = SigningKey, KeyId = "ps-key",
            MissionS256 = variant == "mission"
                ? Base64UrlEncoder.Encode(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("other"))) : mission,
        }.Build();
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var challengeHandler = new ChallengeHandler(
            new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient), new AAuthTokenHolder(AgentToken),
            new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: PsUrl, onInteractionRequired: null, pollerOptions: null)
        {
            InnerHandler = SignedResource(),
        };
        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        using var request = new HttpRequestMessage(HttpMethod.Get, "/data");
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.MissionS256, mission);
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.MissionPersonTokens,
            new Dictionary<string, string> { [variant == "resource" ? "https://other.example" : ResourceUrl] = token });

        if (variant == "match")
        {
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(0, exchangeHandler.PersonServerCalls);
        }
        else
        {
            await Assert.ThrowsAnyAsync<Exception>(() => client.SendAsync(request));
            Assert.True(exchangeHandler.PersonServerCalls > 0);
        }
    }

    [Fact(DisplayName = "ChallengeHandler — upstream token takes precedence over personServer")]
    public async Task UpstreamToken_TakesPrecedenceOverPersonServer()
    {
        var upstreamToken = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "http://localhost:7777",
            ["aud"] = ResourceUrl,
            ["sub"] = "upstream-person",
        }, PersonTokenBuilder.TokenType);

        string? capturedTokenEndpoint = null;
        var exchangeHandler = new CapturingExchangeHandler(req =>
        {
            capturedTokenEndpoint = req.RequestUri?.GetLeftPart(UriPartial.Authority);
        });

        var holder = new AAuthTokenHolder("initial-token");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: PsUrl, // should be ignored
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamTokenProvider: () => upstreamToken)
        {
            InnerHandler = SignedResource(),
        };

        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

        Assert.Equal("http://localhost:7777", capturedTokenEndpoint);
    }

    [Fact(DisplayName = "ChallengeHandler — throws when both personServer and upstreamTokenProvider are null")]
    public void ThrowsWhenBothNull()
    {
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);
        var holder = new AAuthTokenHolder("token");

        Assert.Throws<ArgumentException>(() => new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
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
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        // Use original constructor signature (non-nullable personServer)
        var challengeHandler = new ChallengeHandler(exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)), PsUrl)
        {
            InnerHandler = SignedResource(),
        };

        using var client = new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

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

        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => exchangeClient.ExchangeAsync(
            PsUrl, ResourceToken,
            new TokenExchangeRequest
            {
                PresentedToken = "presented",
                PollerOptions = new DeferredPollerOptions { PreferWaitSeconds = 45 },
            }));

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

        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => exchangeClient.ExchangeAsync(
            PsUrl, ResourceToken,
            new TokenExchangeRequest { PresentedToken = "presented" }));

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
            $"{{\"error\":\"{errorCode}\",\"detail\":\"boom\",\"type\":\"https://example.test/denied\"}}");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        var ex = await Assert.ThrowsAsync<AAuth.Errors.AAuthTokenExchangeException>(
            () => exchangeClient.ExchangeAsync(PsUrl, ResourceToken, "presented"));

        Assert.Equal(errorCode, ex.ErrorCode);
        Assert.Equal("boom", ex.Detail);
        Assert.Equal((int)status, ex.StatusCode);
        Assert.Equal(expectedTerminal, ex.IsTerminal);
    }

    [Fact(DisplayName = "TokenExchangeClient — non-2xx without parseable error falls back to HttpRequestException")]
    public async Task Exchange_NonSuccessWithoutErrorBody_FallsBack()
    {
        var exchangeHandler = new ErrorExchangeHandler(
            HttpStatusCode.BadGateway, "<html>nginx 502</html>");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => exchangeClient.ExchangeAsync(PsUrl, ResourceToken, "presented"));
    }

    [Fact(DisplayName = "TokenExchangeClient — JSON body without 'error' member falls back to HttpRequestException")]
    public async Task Exchange_JsonWithoutError_FallsBack()
    {
        var exchangeHandler = new ErrorExchangeHandler(
            HttpStatusCode.BadRequest, "{\"detail\":\"something\"}");
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => exchangeClient.ExchangeAsync(PsUrl, ResourceToken, "presented"));
    }

    [Theory]
    [InlineData("{\"error\":\"server_error\",\"error_description\":\"legacy\"}")]
    [InlineData("{\"error\":\"server_error\",\"detail\":123,\"type\":\"denied\"}")]
    public async Task Exchange_OnlyUsesStringDetail(string body)
    {
        var handler = new ErrorExchangeHandler(HttpStatusCode.BadRequest, body);
        using var http = new InProcessHttpClient(handler);
        var client = new TokenExchangeClient(http, new MetadataClient(http));
        var error = await Assert.ThrowsAsync<AAuth.Errors.AAuthTokenExchangeException>(
            () => client.ExchangeAsync(PsUrl, ResourceToken, "presented"));
        Assert.Equal("server_error", error.ErrorCode);
        Assert.False(error.IsTerminal);
        Assert.Null(error.Detail);
    }

    [Theory]
    [InlineData("{\"type\":\"denied\",\"detail\":\"no error\"}")]
    [InlineData("{\"error\":42}")]
    [InlineData("{\"error\":{}}")]
    [InlineData("{\"error\":\"\"}")]
    public async Task Exchange_InvalidErrorMember_FallsBack(string body)
    {
        var handler = new ErrorExchangeHandler(HttpStatusCode.Forbidden, body);
        using var http = new InProcessHttpClient(handler);
        var client = new TokenExchangeClient(http, new MetadataClient(http));
        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.ExchangeAsync(PsUrl, ResourceToken, "presented"));
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

        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => exchangeClient.ExchangeAsync(
            PsUrl, ResourceToken,
            new TokenExchangeRequest
            {
                PresentedToken = "presented",
                OnInteractionRequired = onInteractionRequired,
                Capabilities = capabilities,
                Prompt = prompt,
            }));

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
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(exchangeHandler), metaClient);
        holder = new AAuthTokenHolder("initial-token");

        var challengeHandler = new ChallengeHandler(
            exchangeClient, holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)), personServer: PsUrl)
        {
            InnerHandler = resource,
            AdditionalSignatureComponents = seed,
        };

        return new InProcessHttpClient(challengeHandler) { BaseAddress = new Uri(ResourceUrl) };
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

    [Theory]
    [InlineData("signature")]
    [InlineData("origin")]
    [InlineData("sub")]
    [InlineData("key")]
    [InlineData("account")]
    [InlineData("expiry")]
    [InlineData("audience")]
    [InlineData("ps")]
    [InlineData("presented")]
    public async Task InvalidChallengeNeverContactsPersonServerOrRequestsConsent(string failure)
    {
        var token = BuildResourceToken(failure: failure);
        if (failure == "audience")
        {
            var segments = token.Split('.');
            var payload = JsonNode.Parse(Base64UrlEncoder.Decode(segments[1]))!.AsObject();
            payload["aud"] = "https://ps.example/path";
            var input = segments[0] + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
            token = input + "." + Base64UrlEncoder.Encode(SigningKey.Sign(Encoding.ASCII.GetBytes(input)));
        }
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        using var discovery = new InProcessHttpClient(exchangeHandler);
        using var metadata = new MetadataClient(discovery);
        using var jwks = new JwksClient(discovery);
        var consentCalls = 0;
        var holder = new AAuthTokenHolder(AgentToken);
        using var client = new InProcessHttpClient(new ChallengeHandler(new TokenExchangeClient(discovery, metadata),
            holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metadata, jwks, PsUrl,
            (_, _) => { consentCalls++; return Task.CompletedTask; })
        {
            InnerHandler = SignedResource(token, PersonToken),
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, ResourceUrl + "/data");

        await Assert.ThrowsAsync<TokenVerificationException>(() => client.SendAsync(request));

        Assert.Equal(0, exchangeHandler.PersonServerCalls);
        Assert.Equal(0, consentCalls);
        Assert.Equal(AgentToken, holder.Current);
    }

    [Fact]
    public async Task ChallengeUsesPresentedTokenEvenWhenHolderChangesAfterSigning()
    {
        var holder = new AAuthTokenHolder(AgentToken);
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        using var discovery = new InProcessHttpClient(exchangeHandler);
        using var metadata = new MetadataClient(discovery);
        using var jwks = new JwksClient(discovery);
        using var client = new InProcessHttpClient(new ChallengeHandler(new TokenExchangeClient(discovery, metadata),
            holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metadata, jwks, PsUrl)
        {
            InnerHandler = new AAuthSigningHandler(SigningKey, () => holder.Current)
            {
                InnerHandler = new MockResourceHandler(ResourceToken, () => holder.Update("changed-after-signing")),
            },
        });

        var error = await Assert.ThrowsAsync<TokenVerificationException>(() => client.GetAsync(ResourceUrl + "/data"));

        Assert.Contains("locally signed agent-token", error.Message);
        Assert.True(exchangeHandler.PersonServerCalls > 0);
    }

    [Fact(DisplayName = "ChallengeHandler — unknown requirement stays unsatisfied and never contacts the PS")]
    public async Task UnknownRequirement_ReturnsErrorWithoutExchange()
    {
        var exchangeHandler = new CapturingExchangeHandler(_ => { });
        using var discovery = new InProcessHttpClient(exchangeHandler);
        using var metadata = new MetadataClient(discovery);
        using var jwks = new JwksClient(discovery);
        var holder = new AAuthTokenHolder(AgentToken);
        using var client = new InProcessHttpClient(new ChallengeHandler(new TokenExchangeClient(discovery, metadata),
            holder, new TokenVerifier { EgressPolicy = TestEgress.Policy }, metadata, jwks, PsUrl)
        {
            InnerHandler = new AAuthSigningHandler(SigningKey, () => holder.Current)
            {
                InnerHandler = new UnknownRequirementHandler(),
            },
        });

        using var response = await client.GetAsync(ResourceUrl + "/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("requirement=future-token", response.Headers.GetValues(AAuthRequirementHeader.Name).Single());
        Assert.Equal(0, exchangeHandler.PersonServerCalls);
        Assert.Equal(AgentToken, holder.Current);
    }

    private static HttpMessageHandler SignedResource(string? token = null, string? carrier = null) =>
        new AAuthSigningHandler(SigningKey, () => carrier ?? AgentToken)
    {
        InnerHandler = new MockResourceHandler(token),
    };

    private static readonly string PersonToken = new PersonTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = PsUrl, Audience = ResourceUrl, Subject = PersonSubject, TokenId = PersonJti,
        ConfirmationKey = SigningKey, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        Key = SigningKey, KeyId = "ps-key",
    }.Build();

    private static string BuildResourceToken(string? missionS256 = null, string? failure = null, string personServer = PsUrl) => new ResourceTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = failure == "origin" ? "https://other.example" : ResourceUrl,
        Audience = personServer,
        PersonServer = failure == "ps" ? "https://other-ps.example" : personServer,
        Subject = failure == "sub" ? "other-person" : PersonSubject,
        PresentedJti = failure == "presented" ? "other-jti" : PersonJti,
        AgentJkt = failure == "key" ? "wrong-key" : SigningKey.ComputeJwkThumbprint(),
        Key = failure == "signature" ? AAuthKey.Generate() : SigningKey,
        KeyId = "resource-key",
        Account = failure == "account" ? "other-account" : null,
        MissionS256 = missionS256,
        IssuedAt = failure == "expiry" ? DateTimeOffset.UtcNow.AddHours(-1) : null,
    }.Build();

    private static string BuildTokenWithPayload(JsonObject payload, string typ = AuthTokenBuilder.TokenType)
    {
        var header = new JsonObject { ["alg"] = "Ed25519", ["typ"] = typ, ["kid"] = "k1" };
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

    /// <summary>Challenges once: an agent token gets <c>requirement=person-token</c>, any other token a resource token.</summary>
    private sealed class MockResourceHandler(string? token = null, Action? onChallenge = null) : HttpMessageHandler
    {
        private int _callCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var call = Interlocked.Increment(ref _callCount);
            if (call == 1)
            {
                onChallenge?.Invoke();
                var presented = request.Options.TryGetValue(AAuth.Agent.AAuthRequestOptions.PresentedToken, out var value) ? value : null;
                var agentCarrier = presented is null
                    || JsonNode.Parse(Base64UrlEncoder.Decode(presented.Split('.')[0]))?["typ"]?.GetValue<string>() == AgentTokenBuilder.TokenType;
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Headers.TryAddWithoutValidation(
                    AAuthRequirementHeader.Name,
                    agentCarrier ? AAuthRequirementHeader.FormatPersonToken() : AAuthRequirementHeader.FormatAuthToken(token ?? ResourceToken));
                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}"),
            });
        }
    }

    private sealed class UnknownRequirementHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=future-token");
            return Task.FromResult(response);
        }
    }

    /// <summary>
    /// Handler that serves metadata for any well-known request and captures
    /// token endpoint POST requests for assertion.
    /// </summary>
    private sealed class CapturingExchangeHandler : HttpMessageHandler
    {
        public int PersonServerCalls { get; private set; }
        private readonly Action<HttpRequestMessage> _onTokenPost;
        public CapturingExchangeHandler(Action<HttpRequestMessage> onTokenPost) => _onTokenPost = onTokenPost;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.GetLeftPart(UriPartial.Authority) != ResourceUrl)
                PersonServerCalls++;
            if (request.RequestUri.AbsolutePath == "/jwks")
            {
                var key = SigningKey.ToPublicJwk();
                key["kid"] = "resource-key";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(new JsonObject { ["keys"] = new JsonArray(key) }.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }
            // Metadata discovery — return auth_token_endpoint at the same origin
            if (request.RequestUri?.AbsolutePath.Contains("well-known") == true)
            {
                var origin = request.RequestUri.GetLeftPart(UriPartial.Authority);
                var metadata = new JsonObject
                {
                    ["issuer"] = origin,
                    ["auth_token_endpoint"] = $"{origin}/token",
                    ["person_token_endpoint"] = $"{origin}/person",
                    ["jwks_uri"] = $"{origin}/jwks",
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }

            // Token endpoint POST — capture and return auth_token
            _onTokenPost(request);
            var response = request.RequestUri!.AbsolutePath == "/person"
                ? new JsonObject { ["person_token"] = "fake-person-token" }
                : new JsonObject { ["auth_token"] = "fake-auth-token" };
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
                    ["auth_token_endpoint"] = $"{origin}/token",
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/problem+json"),
            });
        }
    }
}
