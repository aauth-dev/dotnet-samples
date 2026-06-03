using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Observability;

/// <summary>
/// Conformance tests for Gap 8 (OpenTelemetry-compatible Activity diagnostics):
/// verifies that server-side middleware sets Activity tags after verification,
/// and client-side operations create child Activity spans.
/// </summary>
public class ActivityDiagnosticsTests : IAsyncLifetime
{
    private const string ApIssuer = "http://localhost:5555";
    private const string PsIssuer = "http://localhost:5555";
    private const string ResourceId = "http://localhost:5000";
    private const string AgentId = "aauth:test@ap.example";
    private const string ResourceScope = "data:read";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    private IHost? _metadataHost;
    private ActivityListener? _listener;
    private readonly List<Activity> _activities = new();

    public async Task InitializeAsync()
    {
        // Subscribe to our AAuth activity source to capture emitted activities.
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AAuthDiagnostics.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity => _activities.Add(activity),
        };
        ActivitySource.AddActivityListener(_listener);

        // Start a mock metadata/JWKS server for AP and PS.
        _metadataHost = await StartMetadataServer();
    }

    public async Task DisposeAsync()
    {
        _listener?.Dispose();
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    // ── Server-side Activity tag tests ─────────────────────────────────────

    /// <summary>
    /// After verification of an agent token (jwt scheme), the middleware
    /// sets <c>aauth.scheme</c>, <c>aauth.level</c>, <c>aauth.agent</c>,
    /// and <c>aauth.token_type</c> on <c>Activity.Current</c>.
    /// </summary>
    [Fact]
    public async Task Middleware_AgentTokenJwt_SetsActivityTags()
    {
        await VerifyActivityTagsViaEndpoint(
            expectedScheme: "jwt",
            expectedLevel: "Identified",
            expectedAgent: AgentId,
            expectedScope: null);
    }

    /// <summary>
    /// After verification of an auth token (jwt scheme), the middleware
    /// sets <c>aauth.scope</c> on <c>Activity.Current</c>.
    /// </summary>
    [Fact]
    public async Task Middleware_AuthTokenJwt_SetsActivityTagsWithScope()
    {
        await VerifyActivityTagsViaEndpoint(
            expectedScheme: "jwt",
            expectedLevel: "Authorized",
            expectedAgent: AgentId,
            expectedScope: ResourceScope);
    }

    /// <summary>
    /// <c>AAuthDiagnostics.Source</c> has the expected source name.
    /// </summary>
    [Fact]
    public void AAuthDiagnostics_SourceName_IsAAuth()
    {
        Assert.Equal("AAuth", AAuthDiagnostics.SourceName);
        Assert.Equal("AAuth", AAuthDiagnostics.Source.Name);
    }

    /// <summary>
    /// <c>AAuthDiagnostics</c> tag constants have expected values.
    /// </summary>
    [Fact]
    public void AAuthDiagnostics_TagConstants_AreCorrect()
    {
        Assert.Equal("aauth.scheme", AAuthDiagnostics.TagScheme);
        Assert.Equal("aauth.level", AAuthDiagnostics.TagLevel);
        Assert.Equal("aauth.agent", AAuthDiagnostics.TagAgent);
        Assert.Equal("aauth.scope", AAuthDiagnostics.TagScope);
        Assert.Equal("aauth.issuer", AAuthDiagnostics.TagIssuer);
        Assert.Equal("aauth.token_type", AAuthDiagnostics.TagTokenType);
        Assert.Equal("aauth.issuer_verified", AAuthDiagnostics.TagIssuerVerified);
    }

    // ── Client-side Activity span tests ────────────────────────────────────

    /// <summary>
    /// <see cref="TokenExchangeClient"/> creates an <c>AAuth.TokenExchange</c>
    /// Activity span during exchange.
    /// </summary>
    [Fact]
    public async Task TokenExchangeClient_CreatesActivitySpan()
    {
        _activities.Clear();

        var stubHandler = new StubHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath.Contains("aauth-person.json"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject
                    {
                        ["token_endpoint"] = "http://localhost:9999/token",
                    }),
                };
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new JsonObject { ["auth_token"] = "at-123" }),
            };
        });

        var httpClient = new HttpClient(stubHandler) { BaseAddress = new Uri("http://localhost:9999/") };
        var metadata = new MetadataClient(httpClient);
        var exchangeClient = new TokenExchangeClient(httpClient, metadata);

        await exchangeClient.ExchangeAsync("http://localhost:9999", "rt-xyz");

        Assert.Contains(_activities, a => a.OperationName == "AAuth.TokenExchange");
    }

    /// <summary>
    /// <see cref="ChallengeHandler"/> creates an <c>AAuth.ChallengeExchange</c>
    /// Activity span when processing a 401 challenge.
    /// </summary>
    [Fact]
    public async Task ChallengeHandler_CreatesActivitySpan()
    {
        _activities.Clear();

        var callCount = 0;
        var agentToken = BuildAgentToken();
        var authToken = BuildAuthToken();

        var stubHandler = new StubHandler(req =>
        {
            callCount++;
            if (req.RequestUri!.AbsolutePath.Contains("aauth-person.json"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject
                    {
                        ["token_endpoint"] = "http://localhost:9998/token",
                    }),
                };
            }
            if (req.RequestUri.AbsolutePath == "/token")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject { ["auth_token"] = authToken }),
                };
            }
            if (callCount <= 2)
            {
                var challengeResp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challengeResp.Headers.TryAddWithoutValidation("AAuth-Requirement",
                    "requirement=auth-token; resource-token=\"rt-fake\"");
                return challengeResp;
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("success"),
            };
        });

        var httpClient = new HttpClient(stubHandler) { BaseAddress = new Uri("http://localhost:9998/") };
        var metadata = new MetadataClient(httpClient);
        var exchange = new TokenExchangeClient(httpClient, metadata);
        var holder = new AAuthTokenHolder(agentToken);

        var challengeHandler = new ChallengeHandler(exchange, holder, "http://localhost:9998")
        {
            InnerHandler = stubHandler,
        };

        using var topClient = new HttpClient(challengeHandler) { BaseAddress = new Uri("http://localhost:9998/") };
        var response = await topClient.GetAsync("/resource");

        Assert.Contains(_activities, a => a.OperationName == "AAuth.ChallengeExchange");
    }

    /// <summary>
    /// Deferred polling creates an <c>AAuth.DeferredPoll</c> Activity span.
    /// </summary>
    [Fact]
    public async Task DeferredPoll_CreatesActivitySpan()
    {
        _activities.Clear();

        var callCount = 0;
        var stubHandler = new StubHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath.Contains("aauth-person.json"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject
                    {
                        ["token_endpoint"] = "http://localhost:9997/token",
                    }),
                };
            }
            if (req.RequestUri.AbsolutePath == "/token")
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Accepted);
                resp.Headers.Location = new Uri("http://localhost:9997/pending/abc");
                resp.Headers.TryAddWithoutValidation("AAuth-Requirement",
                    "requirement=interaction;interact_url=http://localhost:9997/interact");
                return resp;
            }
            if (req.RequestUri.AbsolutePath == "/pending/abc")
            {
                callCount++;
                if (callCount < 2)
                {
                    return new HttpResponseMessage(HttpStatusCode.Accepted);
                }
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject { ["auth_token"] = "deferred-at" }),
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(stubHandler) { BaseAddress = new Uri("http://localhost:9997/") };
        var metadata = new MetadataClient(httpClient);
        var exchange = new TokenExchangeClient(httpClient, metadata);

        await exchange.ExchangeAsync(
            "http://localhost:9997", "rt-xyz",
            new TokenExchangeRequest
            {
                OnInteractionRequired = (_, _) => Task.CompletedTask,
                PollerOptions = new DeferredPollerOptions
                {
                    DefaultPollInterval = TimeSpan.FromMilliseconds(1),
                    MinPollInterval = TimeSpan.Zero,
                },
            });

        Assert.Contains(_activities, a => a.OperationName == "AAuth.TokenExchange");
        Assert.Contains(_activities, a => a.OperationName == "AAuth.DeferredPoll");
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private string BuildAgentToken()
    {
        return new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = _apKey,
            KeyId = "ap-key-1",
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
        }.Build();
    }

    private string BuildAuthToken()
    {
        return new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceId,
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = "ps-key-1",
            Subject = "pairwise-sub",
            Scope = ResourceScope,
            IssuedAt = FixedClock,
        }.Build();
    }

    private async Task VerifyActivityTagsViaEndpoint(
        string expectedScheme, string expectedLevel, string expectedAgent, string? expectedScope)
    {
        Dictionary<string, string?>? capturedTags = null;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp =>
            new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp =>
            new JwksClient(sp.GetRequiredService<HttpClient>()));

        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            RequireIssuerVerification = true,
            TrustedAuthTokenIssuers = new HashSet<string> { PsIssuer },
        });
        app.MapGet("/check-tags", (HttpContext ctx) =>
        {
            var activity = Activity.Current;
            if (activity is not null)
            {
                capturedTags = activity.Tags.ToDictionary(
                    kvp => kvp.Key, kvp => kvp.Value);
            }
            return Results.Ok("ok");
        });
        await app.StartAsync();

        try
        {
            var client = app.GetTestClient();

            string token;
            if (expectedScope is not null)
            {
                token = BuildAuthToken();
            }
            else
            {
                token = BuildAgentToken();
            }

            var signed = await SignRequest(token, "/check-tags");
            var relay = new HttpRequestMessage(HttpMethod.Get, "/check-tags");
            foreach (var h in signed.Headers)
                relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
            relay.Headers.Host = "localhost:5000";
            var response = await client.SendAsync(relay);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.NotNull(capturedTags);
            Assert.Equal(expectedScheme, capturedTags![AAuthDiagnostics.TagScheme]);
            Assert.Equal(expectedLevel, capturedTags[AAuthDiagnostics.TagLevel]);
            if (expectedAgent is not null)
                Assert.Equal(expectedAgent, capturedTags[AAuthDiagnostics.TagAgent]);
            if (expectedScope is not null)
                Assert.Equal(expectedScope, capturedTags[AAuthDiagnostics.TagScope]);
        }
        finally
        {
            await app.StopAsync();
            ((IDisposable)app).Dispose();
        }
    }

    private async Task<HttpRequestMessage> SignRequest(string token, string path)
    {
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => token);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"http://localhost:5000{path}"));
        return capture.Captured!;
    }

    private async Task<IHost> StartMetadataServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        // AP metadata at /.well-known/aauth-agent.json
        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = ApIssuer,
            jwks_uri = $"{ApIssuer}/.well-known/ap-jwks.json",
        }));

        // PS metadata at /.well-known/aauth-person.json
        app.MapGet("/.well-known/aauth-person.json", () => Results.Json(new
        {
            issuer = PsIssuer,
            jwks_uri = $"{PsIssuer}/.well-known/ps-jwks.json",
            token_endpoint = $"{PsIssuer}/token",
        }));

        // AP JWKS
        app.MapGet("/.well-known/ap-jwks.json", () =>
        {
            var jwk = _apKey.ToPublicJwk();
            jwk["kid"] = "ap-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        // PS JWKS
        app.MapGet("/.well-known/ps-jwks.json", () =>
        {
            var jwk = _psKey.ToPublicJwk();
            jwk["kid"] = "ps-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        await app.StartAsync();
        return app;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
            => _handler = handler;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_handler(request));
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
