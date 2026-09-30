using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
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
        builder.Services.AddSingleton(new AAuthVerifier { TimeProvider = new FixedTimeProvider() });
        builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore(new FixedTimeProvider()));
        var app = builder.Build();
        app.UseAAuthVerification(options =>
        {
            options.AcceptedSchemes = AAuthVerificationOptions.Generic().AcceptedSchemes;
            options.TimeProvider = new FixedTimeProvider();
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

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => FixedClock;
    }

    [Fact(DisplayName = "§jkt-jwt — valid naming JWT with future exp succeeds")]
    public async Task ValidNamingJwt_Succeeds()
    {
        var namingJwt = await BuildNamingJwtAsync(exp: FixedClock.AddMinutes(5));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — expired naming JWT returns 401")]
    public async Task ExpiredNamingJwt_Returns401()
    {
        // exp is 2 minutes in the past (beyond 30s clock skew)
        var namingJwt = await BuildNamingJwtAsync(exp: FixedClock.AddMinutes(-2));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — naming JWT expired within clock skew still succeeds")]
    public async Task NamingJwtExpiredWithinClockSkew_Succeeds()
    {
        // exp is 10 seconds in the past (within 30s clock skew)
        var namingJwt = await BuildNamingJwtAsync(exp: FixedClock.AddSeconds(-10));
        var response = await SendSignedRequest(namingJwt);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — replay detection rejects duplicate jti")]
    public async Task DuplicateJti_Returns401()
    {
        var fixedJti = "replay-test-jti-12345";
        var namingJwt = await BuildNamingJwtAsync(exp: FixedClock.AddMinutes(5), jti: fixedJti);

        // First request succeeds
        var signed = await SignAsync(namingJwt);
        var response1 = await RelayAsync(signed);
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        // Replaying the same signed request is rejected
        var response2 = await RelayAsync(signed);
        Assert.Equal(HttpStatusCode.Unauthorized, response2.StatusCode);
    }

    [Fact(DisplayName = "§jkt-jwt — different jti values both succeed")]
    public async Task DifferentJti_BothSucceed()
    {
        var jwt1 = await BuildNamingJwtAsync(exp: FixedClock.AddMinutes(5), jti: "unique-1");
        var jwt2 = await BuildNamingJwtAsync(exp: FixedClock.AddMinutes(5), jti: "unique-2");

        var response1 = await SendSignedRequest(jwt1);
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var response2 = await SendSignedRequest(jwt2);
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    [Fact(DisplayName = "§3.4 — spoofed iss (claims another key's thumbprint) returns 401")]
    public async Task SpoofedIss_Returns401()
    {
        // Attacker signs with their OWN durable key but claims the legitimate
        // durable key's thumbprint as iss. Self-anchoring computes the thumbprint
        // from the header jwk (attacker's) and finds it != iss → reject.
        var attackerDurable = AAuthKey.Generate();
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = attackerDurable.ToPublicJwk(),
        };
        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + _durableKey.ComputeJwkThumbprint(),
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = FixedClock.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = _ephemeralKey.ToPublicJwk() },
        };
        var spoofed = await JwtWriter.SignCompactAsync(header, payload, attackerDurable);

        var response = await SendSignedRequest(spoofed);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§3.4 — naming JWT signed by a non-header key returns 401")]
    public async Task ForgedSignature_Returns401()
    {
        // Header advertises the durable key, but the JWT is signed by a different
        // key — the §3.4 signature check (step 8) against the header jwk fails.
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = _durableKey.ToPublicJwk(),
        };
        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + _durableKey.ComputeJwkThumbprint(),
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = FixedClock.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = _ephemeralKey.ToPublicJwk() },
        };
        var forged = await JwtWriter.SignCompactAsync(header, payload, AAuthKey.Generate());

        var response = await SendSignedRequest(forged);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "§3.4 — unsupported naming JWT typ returns 401")]
    public async Task WrongTyp_Returns401()
    {
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = "naming+jwt", // retired/unsupported typ
            ["jwk"] = _durableKey.ToPublicJwk(),
        };
        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + _durableKey.ComputeJwkThumbprint(),
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = FixedClock.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = _ephemeralKey.ToPublicJwk() },
        };
        var wrongTyp = await JwtWriter.SignCompactAsync(header, payload, _durableKey);

        var response = await SendSignedRequest(wrongTyp);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private async Task<string> BuildNamingJwtAsync(DateTimeOffset exp, string? jti = null)
    {
        // draft-hardt-httpbis-signature-key-04 §3.4 self-issued naming JWT.
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = _durableKey.ToPublicJwk(),
        };

        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + _durableKey.ComputeJwkThumbprint(),
            ["iat"] = FixedClock.AddMinutes(-5).ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject
            {
                ["jwk"] = _ephemeralKey.ToPublicJwk(),
            },
        };

        return await JwtWriter.SignCompactAsync(header, payload, _durableKey);
    }

    private async Task<HttpResponseMessage> SendSignedRequest(string namingJwt)
        => await RelayAsync(await SignAsync(namingJwt));

    private async Task<HttpRequestMessage> SignAsync(string namingJwt)
    {
        // Sign a request targeting the test server's host
        var capture = new CaptureHandler();
        var signingHandler = new AAuthSigningHandler(
            _ephemeralKey,
            new JktJwtSignatureKeyProvider(() => namingJwt),
            new FixedTimeProvider())
        {
            InnerHandler = capture,
        };
        using var signingClient = new InProcessHttpClient(signingHandler);
        await signingClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/jkt-jwt"));
        return capture.Captured!;
    }

    private async Task<HttpResponseMessage> RelayAsync(HttpRequestMessage signed)
    {
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
