using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.Errors;
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

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for <see cref="AAuthFullVerificationMiddleware"/>:
/// verifies that JWT issuer signatures are checked (Gaps 1 and 2) in addition
/// to HTTP signature PoP.
/// </summary>
public class FullVerificationMiddlewareTests : IAsyncLifetime
{
    // ── Test fixtures ──────────────────────────────────────────────────────

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
        // Start a mock metadata/JWKS server for AP and PS.
        _metadataHost = await StartMetadataServer();

        // Start the resource server with full verification middleware.
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost.GetTestClient());
        builder.Services.AddSingleton(sp =>
            new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp =>
            new JwksClient(sp.GetRequiredService<HttpClient>()));

        var app = builder.Build();
        app.UseAAuthFullVerification(new FullVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            RequireIssuerVerification = true,
        });
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

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
            Scope = "whoami",
            IssuedAt = FixedClock,
        }.Build();
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
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));
        return capture.Captured!;
    }

    private async Task<HttpResponseMessage> SendSigned(string token)
    {
        var signed = await SignRequest(token);
        // Relay to the test server.
        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
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

    [Fact(DisplayName = "§Full Verification — accepts AP-issued agent token with valid JWKS")]
    public async Task AcceptsValidAgentToken()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — accepts valid auth token with PS JWKS")]
    public async Task AcceptsValidAuthToken()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects agent token signed by unknown key")]
    public async Task RejectsAgentTokenWithUnknownKey()
    {
        // Sign the agent token with a different key than the AP's published JWKS.
        var forgerKey = AAuthKey.Generate();
        var forgedToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = forgerKey, // Wrong key — not in AP JWKS
            KeyId = "ap-key-1", // Claims to be AP's key
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
        }.Build();

        var response = await SendSigned(forgedToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects auth token signed by unknown key")]
    public async Task RejectsAuthTokenWithUnknownKey()
    {
        var forgerKey = AAuthKey.Generate();
        var forgedToken = new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceId,
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = forgerKey, // Wrong key — not in PS JWKS
            KeyId = "ps-key-1",
            Subject = "pairwise-sub",
            Scope = "whoami",
            IssuedAt = FixedClock,
        }.Build();

        var response = await SendSigned(forgedToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects auth token with wrong audience")]
    public async Task RejectsAuthTokenWithWrongAudience()
    {
        var wrongAudToken = new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = "https://wrong-resource.example", // Wrong audience
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = "ps-key-1",
            Subject = "pairwise-sub",
            Scope = "whoami",
            IssuedAt = FixedClock,
        }.Build();

        var response = await SendSigned(wrongAudToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects agent token from untrusted issuer")]
    public async Task RejectsAgentTokenFromUntrustedIssuer()
    {
        // Reconfigure with an issuer allow-list.
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>()));
        var app = builder.Build();
        app.UseAAuthFullVerification(new FullVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            TrustedAgentProviderIssuers = new HashSet<string> { "https://trusted-only.example" },
        });
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        _host = app;

        var token = BuildAgentToken(); // Issuer = ApIssuer, NOT in allow-list
        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects auth token from untrusted PS issuer")]
    public async Task RejectsAuthTokenFromUntrustedPsIssuer()
    {
        // Reconfigure with an auth token issuer allow-list.
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>()));
        var app = builder.Build();
        app.UseAAuthFullVerification(new FullVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            TrustedAuthTokenIssuers = new HashSet<string> { "https://trusted-ps-only.example" },
        });
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        _host = app;

        var token = BuildAuthToken(); // Issuer = PsIssuer, NOT in PS allow-list
        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — rejects auth token missing act claim")]
    public async Task RejectsAuthTokenMissingAct()
    {
        // Manually construct a token without the act claim.
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Algorithm,
            ["typ"] = AuthTokenBuilder.TokenType,
            ["kid"] = "ps-key-1",
        };
        var payload = new JsonObject
        {
            ["iss"] = PsIssuer,
            ["dwk"] = AuthTokenBuilder.PersonDwk,
            ["aud"] = ResourceId,
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["agent"] = AgentId,
            ["cnf"] = new JsonObject { ["jwk"] = _agentKey.ToPublicJwk() },
            // NO act claim
            ["sub"] = "pairwise-sub",
            ["scope"] = "whoami",
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = FixedClock.AddHours(1).ToUnixTimeSeconds(),
        };
        var token = JwtWriter.SignCompact(header, payload, _psKey);

        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — missing headers returns 401")]
    public async Task MissingHeaders_Returns401()
    {
        var response = await _host!.GetTestClient().GetAsync("/protected");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — hwk scheme passes without JWT verification")]
    public async Task HwkScheme_PassesWithoutJwtVerification()
    {
        // hwk has no JWT to verify — should pass with PoP only.
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var provider = new HwkSignatureKeyProvider(key);
        var handler = new AAuthSigningHandler(key, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));
        var signed = capture.Captured!;

        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";

        var response = await _host!.GetTestClient().SendAsync(relay);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — self-issued agent token passes")]
    public async Task SelfIssuedAgentToken_Passes()
    {
        // Self-issued: kid == thumbprint of cnf.jwk.
        var selfKey = AAuthKey.Generate();
        var thumbprint = selfKey.ComputeJwkThumbprint();
        var selfToken = new AgentTokenBuilder
        {
            Issuer = "http://localhost:8888", // Self-issued — doesn't need AP JWKS
            Subject = "aauth:self@self.example",
            Key = selfKey, // Self-signed
            KeyId = thumbprint, // kid == thumbprint signals self-issued
            ConfirmationKey = selfKey,
            IssuedAt = FixedClock,
        }.Build();

        // For self-issued, the agent signs with its own key.
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => selfToken);
        var handler = new AAuthSigningHandler(selfKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));
        var signed = capture.Captured!;

        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";

        var response = await _host!.GetTestClient().SendAsync(relay);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Full Verification — stores FullVerificationResult in HttpContext.Items")]
    public async Task StoresVerificationResult()
    {
        // Reconfigure to expose the result.
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>()));
        var app = builder.Build();
        app.UseAAuthFullVerification(new FullVerificationOptions
        {
            ResourceIdentifier = ResourceId,
        });
        app.MapGet("/protected", (HttpContext ctx) =>
        {
            var result = ctx.Items[AAuthFullVerificationMiddleware.ContextItemKey] as FullVerificationResult;
            return Results.Json(new
            {
                scheme = result?.Scheme,
                tokenType = result?.TokenType,
                issuer = result?.Issuer,
                agent = result?.Agent,
                issuerVerified = result?.IssuerVerified,
            });
        });
        await app.StartAsync();
        _host = app;

        var token = BuildAgentToken();
        var response = await SendSigned(token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("jwt", (string?)body?["scheme"]);
        Assert.Equal(AgentTokenBuilder.TokenType, (string?)body?["tokenType"]);
        Assert.Equal(ApIssuer, (string?)body?["issuer"]);
        Assert.True((bool?)body?["issuerVerified"]);
    }
}
