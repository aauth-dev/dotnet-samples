using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for <see cref="AAuthAuthenticationHandler"/>,
/// <see cref="AAuthVerificationResult"/>, and authorization policies (Gaps 5-6).
/// </summary>
public class AuthorizationIntegrationTests : IAsyncLifetime
{
    private const string ApIssuer = "http://localhost:5555";
    private const string PsIssuer = "http://localhost:5555";
    private const string ResourceId = "http://localhost:5000";
    private const string AgentId = "aauth:test@ap.example";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    private IHost? _host;
    private IHost? _metadataHost;

    public async Task InitializeAsync()
    {
        _metadataHost = await StartMetadataServer();
        _host = await StartResourceServer();
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

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

    private async Task<IHost> StartResourceServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp =>
            new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp =>
            new JwksClient(sp.GetRequiredService<HttpClient>()));

        // Register AAuth authentication + authorization.
        builder.Services.AddAAuthAuthentication();
        builder.Services.AddAAuthAuthorization();
        builder.Services.AddAAuthScopePolicy("AAuth.Scope.whoami", "whoami");
        builder.Services.AddAAuthScopePolicy("AAuth.Scope.admin", "admin");

        var app = builder.Build();

        // Verification middleware populates Features.
        app.UseAAuthFullVerification(new FullVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            RequireIssuerVerification = true,
        });
        app.UseAuthentication();
        app.UseAuthorization();

        // Endpoints with different authorization requirements.
        app.MapGet("/open", () => Results.Ok("open"));
        app.MapGet("/authenticated", () => Results.Ok("authenticated"))
            .RequireAuthorization("AAuth.Authenticated");
        app.MapGet("/identified", () => Results.Ok("identified"))
            .RequireAuthorization("AAuth.Identified");
        app.MapGet("/authorized", () => Results.Ok("authorized"))
            .RequireAuthorization("AAuth.Authorized");
        app.MapGet("/scoped-whoami", () => Results.Ok("scoped"))
            .RequireAuthorization("AAuth.Scope.whoami");
        app.MapGet("/scoped-admin", () => Results.Ok("admin"))
            .RequireAuthorization("AAuth.Scope.admin");
        app.MapGet("/claims", (HttpContext ctx) =>
        {
            var user = ctx.User;
            return Results.Json(new
            {
                isAuthenticated = user.Identity?.IsAuthenticated,
                level = user.FindFirst(AAuthAuthenticationHandler.LevelClaimType)?.Value,
                agent = user.FindFirst(AAuthAuthenticationHandler.AgentClaimType)?.Value,
                jkt = user.FindFirst(AAuthAuthenticationHandler.JktClaimType)?.Value,
                issuer = user.FindFirst(AAuthAuthenticationHandler.IssuerClaimType)?.Value,
                subject = user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                actSub = user.FindFirst(AAuthAuthenticationHandler.ActorSubjectClaimType)?.Value,
                scopes = user.FindAll(AAuthAuthenticationHandler.ScopeClaimType)
                    .Select(c => c.Value).ToArray(),
            });
        }).RequireAuthorization("AAuth.Authenticated");

        await app.StartAsync();
        return app;
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

    private string BuildAuthToken(string scope = "whoami")
    {
        return new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceId,
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = "ps-key-1",
            Subject = "pairwise-sub-123",
            Scope = scope,
            IssuedAt = FixedClock,
        }.Build();
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

    private async Task<HttpResponseMessage> SendSigned(string token, string path)
    {
        var signed = await SignRequest(token, path);
        var relay = new HttpRequestMessage(HttpMethod.Get, path);
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";
        return await _host!.GetTestClient().SendAsync(relay);
    }

    private async Task<HttpResponseMessage> SendHwk(string path)
    {
        var capture = new CaptureHandler();
        var provider = new HwkSignatureKeyProvider(_agentKey);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"http://localhost:5000{path}"));
        var signed = capture.Captured!;
        var relay = new HttpRequestMessage(HttpMethod.Get, path);
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";
        return await _host!.GetTestClient().SendAsync(relay);
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

    // ── Tests ──────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Auth — AAuthVerificationResult stored in HttpContext.Features")]
    public async Task VerificationResultStoredInFeatures()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(token, "/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — HttpContext.User populated with AAuth claims")]
    public async Task UserPopulatedWithClaims()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(token, "/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        Assert.Equal(true, (bool?)json["isAuthenticated"]);
        Assert.Equal("Authorized", (string?)json["level"]);
        Assert.Equal(AgentId, (string?)json["agent"]);
        Assert.Equal(ApIssuer, (string?)json["issuer"]);  // auth token issuer = PS
        Assert.Equal("pairwise-sub-123", (string?)json["subject"]);
        Assert.NotNull((string?)json["jkt"]);
    }

    [Fact(DisplayName = "§Auth — agent token maps to Identified level")]
    public async Task AgentTokenMapsToIdentified()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(token, "/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        Assert.Equal("Identified", (string?)json["level"]);
        Assert.Equal(AgentId, (string?)json["agent"]);
    }

    [Fact(DisplayName = "§Auth — hwk scheme maps to Pseudonymous level")]
    public async Task HwkMapsToPseudonymous()
    {
        var response = await SendHwk("/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        Assert.Equal("Pseudonymous", (string?)json["level"]);
        Assert.NotNull((string?)json["jkt"]);
    }

    [Fact(DisplayName = "§Auth — [Authorize(AAuth.Authorized)] requires auth token")]
    public async Task AuthorizedPolicyRequiresAuthToken()
    {
        // Agent token (Identified) should be rejected by Authorized policy.
        var agentToken = BuildAgentToken();
        var response = await SendSigned(agentToken, "/authorized");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        // Auth token (Authorized) should pass.
        var authToken = BuildAuthToken();
        response = await SendSigned(authToken, "/authorized");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — [Authorize(AAuth.Identified)] accepts agent and auth tokens")]
    public async Task IdentifiedPolicyAcceptsBoth()
    {
        var agentToken = BuildAgentToken();
        var response = await SendSigned(agentToken, "/identified");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var authToken = BuildAuthToken();
        response = await SendSigned(authToken, "/identified");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — [Authorize(AAuth.Identified)] rejects hwk (Pseudonymous)")]
    public async Task IdentifiedPolicyRejectsHwk()
    {
        var response = await SendHwk("/identified");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — scope policy accepts matching scope")]
    public async Task ScopePolicyAcceptsMatchingScope()
    {
        var token = BuildAuthToken("whoami");
        var response = await SendSigned(token, "/scoped-whoami");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — scope policy rejects missing scope (403)")]
    public async Task ScopePolicyRejectsMissingScope()
    {
        // Token has "whoami" scope, endpoint requires "admin".
        var token = BuildAuthToken("whoami");
        var response = await SendSigned(token, "/scoped-admin");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact(DisplayName = "§Auth — User.HasClaim works with AAuth claims")]
    public async Task UserHasClaimWorks()
    {
        var token = BuildAuthToken("whoami data:read");
        var response = await SendSigned(token, "/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        var scopes = json["scopes"]!.AsArray().Select(n => n!.GetValue<string>()).ToList();
        Assert.Contains("whoami", scopes);
        Assert.Contains("data:read", scopes);
    }

    [Fact(DisplayName = "§Auth — auth token carries act.sub as claim")]
    public async Task AuthTokenCarriesActSub()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(token, "/claims");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        // AuthTokenBuilder sets act.sub = Agent
        Assert.Equal(AgentId, (string?)json["actSub"]);
    }
}
