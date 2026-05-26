using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.Headers;
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

namespace AAuth.Conformance.CallChaining;

/// <summary>
/// Conformance tests for <see cref="AAuthApplicationBuilderExtensions.UseAAuthIntermediary"/>
/// verifying it composes verification + challenge middleware correctly.
/// </summary>
public class UseAAuthIntermediaryTests : IAsyncLifetime
{
    private const string ApIssuer = "http://localhost:5555";
    private const string PsIssuer = "http://localhost:5555";
    private const string ResourceId = "http://localhost:6000";
    private const string AgentId = "aauth:test@ap.example";
    private const string ResourceKid = "resource-key-1";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly AAuthKey _resourceKey = AAuthKey.Generate();

    private IHost? _metadataHost;
    private IHost? _intermediaryHost;

    public async Task InitializeAsync()
    {
        _metadataHost = await StartMetadataServer();
        _intermediaryHost = await StartIntermediaryServer();
    }

    public async Task DisposeAsync()
    {
        if (_intermediaryHost is not null) { await _intermediaryHost.StopAsync(); _intermediaryHost.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    [Fact(DisplayName = "UseAAuthIntermediary — rejects agent token with 401 + resource token challenge")]
    public async Task RejectsAgentToken_With401Challenge()
    {
        var agentToken = BuildAgentToken();
        var response = await SendSigned(agentToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains(AAuthRequirementHeader.Name));

        var headerValue = string.Join("", response.Headers.GetValues(AAuthRequirementHeader.Name));
        var parsed = AAuthRequirementHeader.Parse(headerValue);
        Assert.Equal(AAuthRequirementHeader.AuthTokenRequirement, parsed.Requirement);
        Assert.NotNull(parsed.ResourceToken);
    }

    [Fact(DisplayName = "UseAAuthIntermediary — passes auth token through to handler")]
    public async Task PassesAuthToken_Through()
    {
        var authToken = BuildAuthToken();
        var response = await SendSigned(authToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("hello", body);
    }

    [Fact(DisplayName = "UseAAuthIntermediary — unsigned request rejected by verification")]
    public async Task UnsignedRequest_RejectedByVerification()
    {
        // Raw request without signature headers → verification fails
        using var client = _intermediaryHost!.GetTestClient();
        var response = await client.GetAsync("/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── Server setup ────────────────────────────────────────────────────────

    private async Task<IHost> StartMetadataServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = ApIssuer,
            jwks_uri = $"{ApIssuer}/.well-known/ap-jwks.json",
        }));

        app.MapGet("/.well-known/aauth-person.json", () => Results.Json(new
        {
            issuer = PsIssuer,
            jwks_uri = $"{PsIssuer}/.well-known/ps-jwks.json",
            token_endpoint = $"{PsIssuer}/token",
        }));

        app.MapGet("/.well-known/ap-jwks.json", () =>
        {
            var jwk = _apKey.ToPublicJwk();
            jwk["kid"] = "ap-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

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

    private async Task<IHost> StartIntermediaryServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp =>
            new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp =>
            new JwksClient(sp.GetRequiredService<HttpClient>()));

        var app = builder.Build();

        app.UseAAuthIntermediary(
            new AAuthVerificationOptions
            {
                ResourceIdentifier = ResourceId,
                RequireIssuerVerification = true,
            },
            new ChallengeOptions
            {
                AccessMode = AAuthAccessMode.RequireAuthToken,
                ResourceSigningKey = _resourceKey,
                ResourceKeyId = ResourceKid,
                ResourceIdentifier = ResourceId,
            });

        app.MapGet("/protected", () => Results.Text("hello"));

        await app.StartAsync();
        return app;
    }

    // ── Signing + token helpers ─────────────────────────────────────────────

    private async Task<HttpResponseMessage> SendSigned(string token)
    {
        var signed = await SignRequest(token);
        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:6000";
        return await _intermediaryHost!.GetTestClient().SendAsync(relay);
    }

    private async Task<HttpRequestMessage> SignRequest(string token)
    {
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => token);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{ResourceId}/protected"));
        return capture.Captured!;
    }

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
            PersonServer = PsIssuer,
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
            Scope = "data:read",
            IssuedAt = FixedClock,
        }.Build();
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
