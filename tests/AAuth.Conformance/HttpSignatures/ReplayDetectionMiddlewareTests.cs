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
using Microsoft.Extensions.Time.Testing;
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
    private readonly EcdsaAAuthKey _agentKey = EcdsaAAuthKey.Generate();
    private readonly InMemoryJtiStore _jtiStore = new();
    private int _sideEffects;

    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { TimeProvider = new FakeTimeProvider(FixedClock) });
        // Registering an IJtiStore turns on replay detection in the middleware.
        builder.Services.AddSingleton<IJtiStore>(_jtiStore);
        var discovery = new InProcessHttpClient(new IssuerDiscoveryFixture(PsIssuer, _psKey, "ps-key-1"));
        builder.Services.AddSingleton(new AAuth.Discovery.MetadataClient(discovery));
        builder.Services.AddSingleton(new AAuth.Discovery.JwksClient(discovery));

        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            EgressPolicy = TestEgress.Policy,
            ResourceIdentifier = ResourceId,
            // PoP signature + replay are what we exercise here; the auth token's
            // issuer trust chain is covered elsewhere.
        });
        app.MapGet("/protected", () => { _sideEffects++; return Results.Ok("hello"); });
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

    [Fact(DisplayName = "§Token Revocation — a revoked auth token jti is rejected with revoked_jwt")]
    public async Task RevokedAuthToken_Rejected()
    {
        // Revocation is keyed on the token's own jti (not the replay tuple).
        const string Jti = "revoked-jti-1";
        var token = BuildAuthToken(Jti);
        Assert.Equal(HttpStatusCode.OK, (await Send(await SignRequest(token, FixedClock.AddSeconds(-2)))).StatusCode);
        await _jtiStore.RevokeAsync(new TokenKey(PsIssuer, Jti), FixedClock.AddMinutes(5));

        var response = await Send(await SignRequest(token, FixedClock.AddSeconds(-1)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            "error=revoked_jwt",
            response.Headers.GetValues(SignatureError.HeaderName).First());
    }

    [Fact]
    public async Task Es256AlternateSignature_RejectedAsReplay()
    {
        var signed = await SignRequest(BuildAuthToken(), FixedClock.AddSeconds(-1));
        Assert.Equal(HttpStatusCode.OK, (await Send(signed)).StatusCode);
        var signature = Convert.FromBase64String(signed.Headers.GetValues("Signature").Single().Split(':')[1]);
        var order = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-256").N;
        var scalar = new Org.BouncyCastle.Math.BigInteger(1, signature, 32, 32);
        var alternate = order.Subtract(scalar).ToByteArrayUnsigned();
        signature.AsSpan(32).Clear();
        alternate.CopyTo(signature.AsSpan(64 - alternate.Length));
        signed.Headers.Remove("Signature");
        signed.Headers.TryAddWithoutValidation("Signature", "sig=:" + Convert.ToBase64String(signature) + ":");
        new AAuthVerifier { TimeProvider = new FakeTimeProvider(FixedClock) }.Verify("GET", "localhost:5000", "/protected",
            signed.Headers.GetValues("Signature-Key").Single(), signed.Headers.GetValues("Signature-Input").Single(),
            signed.Headers.GetValues("Signature").Single(), _agentKey);

        var replay = await Send(signed);

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(1, _sideEffects);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private string BuildAuthToken(string? jti = null)
        => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = PsIssuer,
            Audience = ResourceId,
            PersonServer = PsIssuer,
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
        var handler = new AAuthSigningHandler(_agentKey, provider, new FakeTimeProvider(created))
        {
            InnerHandler = capture,
        };
        using var client = new InProcessHttpClient(handler);
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
