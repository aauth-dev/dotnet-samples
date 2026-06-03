using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth;
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
/// Tests for naming JWT validation in the jkt-jwt scheme:
/// - exp (expiration) enforcement
/// - jti (replay detection) when IJtiStore is registered
/// </summary>
public class NamingJwtValidationTests : IAsyncLifetime
{
    private static readonly DateTimeOffset FixedClock = new(2026, 5, 27, 12, 0, 0, TimeSpan.Zero);

    private readonly AAuthKey _durableKey = AAuthKey.Generate();
    private readonly AAuthKey _ephemeralKey = AAuthKey.Generate();

    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<IJtiStore, InMemoryJtiStore>();
        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            RequireIssuerVerification = false,
            Clock = () => FixedClock,
            ClockSkew = TimeSpan.FromSeconds(30),
        });
        app.MapGet("/jkt-jwt", () => Results.Ok("ok"));
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
    }

    private HttpClient Client => _host!.GetTestClient();

    [Fact(DisplayName = "§jkt-jwt — valid naming JWT with future exp succeeds")]
    public async Task ValidNamingJwt_Succeeds()
    {
        var namingJwt = BuildNamingJwt(exp: FixedClock.AddMinutes(5));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — expired naming JWT returns 401")]
    public async Task ExpiredNamingJwt_Returns401()
    {
        // exp is 2 minutes in the past (beyond 30s clock skew)
        var namingJwt = BuildNamingJwt(exp: FixedClock.AddMinutes(-2));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — naming JWT expired within clock skew still succeeds")]
    public async Task NamingJwtExpiredWithinClockSkew_Succeeds()
    {
        // exp is 10 seconds in the past (within 30s clock skew)
        var namingJwt = BuildNamingJwt(exp: FixedClock.AddSeconds(-10));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — replay detection rejects duplicate jti")]
    public async Task DuplicateJti_Returns401()
    {
        var fixedJti = "replay-test-jti-12345";
        var namingJwt = BuildNamingJwt(exp: FixedClock.AddMinutes(5), jti: fixedJti);

        // First request succeeds
        var response1 = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        // Second request with same jti is rejected
        var response2 = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, response2.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — different jti values both succeed")]
    public async Task DifferentJti_BothSucceed()
    {
        var jwt1 = BuildNamingJwt(exp: FixedClock.AddMinutes(5), jti: "unique-1");
        var jwt2 = BuildNamingJwt(exp: FixedClock.AddMinutes(5), jti: "unique-2");

        var response1 = await SendSignedRequest(jwt1);
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var response2 = await SendSignedRequest(jwt2);
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private string BuildNamingJwt(DateTimeOffset exp, string? jti = null)
    {
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Algorithm,
            ["typ"] = "naming+jwt",
            ["kid"] = _durableKey.ComputeJwkThumbprint(),
        };

        var payload = new JsonObject
        {
            ["iss"] = "https://ap.example",
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject
            {
                ["jwk"] = _ephemeralKey.ToPublicJwk(),
            },
        };

        return JwtWriter.SignCompact(header, payload, _durableKey);
    }

    private async Task<HttpResponseMessage> SendSignedRequest(string namingJwt)
    {
        // Sign a request targeting the test server's host
        var capture = new CaptureHandler();
        var signingHandler = new AAuthSigningHandler(
            _ephemeralKey,
            new JktJwtSignatureKeyProvider(_ephemeralKey, () => namingJwt),
            () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var signingClient = new HttpClient(signingHandler);
        await signingClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/jkt-jwt"));
        var signed = capture.Captured!;

        // Relay the signed headers to the test server
        var relay = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jkt-jwt");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);

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
}
