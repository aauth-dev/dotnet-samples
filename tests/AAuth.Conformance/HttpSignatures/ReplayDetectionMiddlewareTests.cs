using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server;
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
/// Conformance tests for <see cref="AAuthVerificationMiddleware"/> replay
/// detection (§Freshness and Replay). Replay is keyed on the per-request
/// signature tuple <c>(signing-key-thumbprint, created, @method, @authority,
/// @path)</c> — NOT the carrier token's <c>jti</c> — so a reusable auth token
/// can be presented on many requests while an exact captured-signature replay
/// within the freshness window is rejected. The carrier <c>jti</c> is retained
/// only for revocation.
/// </summary>
public class ReplayDetectionMiddlewareTests : IAsyncLifetime
{
    private const string ResourceId = "http://localhost:5000";
    private const string PsIssuer = "http://localhost:5555";
    private const string AgentId = "aauth:test@ap.example";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly InMemoryJtiStore _jtiStore = new();

    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        // Registering an IJtiStore turns on replay detection in the middleware.
        builder.Services.AddSingleton<IJtiStore>(_jtiStore);

        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            // PoP signature + replay are what we exercise here; the auth token's
            // issuer trust chain is covered elsewhere.
            RequireIssuerVerification = false,
        });
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
    }

    [Fact(DisplayName = "§Freshness — the same auth token reused across requests is accepted")]
    public async Task ReusedAuthToken_FreshSignatures_Accepted()
    {
        // One auth token (one jti), presented on two requests with distinct
        // per-request signatures (different `created`). Both MUST pass — keying
        // replay on the token jti would have rejected the second.
        var token = BuildAuthToken();

        var first = await Send(await SignRequest(token, FixedClock.AddSeconds(-2)));
        var second = await Send(await SignRequest(token, FixedClock.AddSeconds(-1)));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    [Fact(DisplayName = "§Freshness — an exact captured-signature replay is rejected")]
    public async Task ExactSignatureReplay_Rejected()
    {
        // The identical signed request (same signature tuple) presented twice:
        // the first records the tuple, the second collides and is rejected.
        var token = BuildAuthToken();
        var signed = await SignRequest(token, FixedClock.AddSeconds(-1));

        var first = await Send(signed);
        var second = await Send(signed);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        Assert.Contains(
            "invalid_jwt",
            second.Headers.GetValues(SignatureError.HeaderName).First());
    }

    [Fact(DisplayName = "§Revocation — a revoked auth token jti is rejected")]
    public async Task RevokedAuthToken_Rejected()
    {
        // Revocation is keyed on the token's own jti (not the replay tuple).
        const string Jti = "revoked-jti-1";
        var token = BuildAuthToken(Jti);
        await _jtiStore.RevokeAsync(Jti);

        var response = await Send(await SignRequest(token, FixedClock.AddSeconds(-1)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            "invalid_jwt",
            response.Headers.GetValues(SignatureError.HeaderName).First());
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private string BuildAuthToken(string? jti = null)
        => new AuthTokenBuilder
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
            TokenId = jti,
        }.Build();

    // Produce a GET /protected signed by the agent key + auth-token carrier,
    // with the signature `created` pinned to a chosen instant.
    private async Task<HttpRequestMessage> SignRequest(string token, DateTimeOffset created)
    {
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => token);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => created)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));
        return capture.Captured!;
    }

    // Relay the captured headers to the test server. Builds a fresh request each
    // call, so passing the same signed message twice is an exact replay.
    private async Task<HttpResponseMessage> Send(HttpRequestMessage signed)
    {
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
}
