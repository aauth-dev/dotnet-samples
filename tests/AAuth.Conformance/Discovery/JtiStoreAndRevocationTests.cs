using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
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

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance tests for the JTI store (replay detection) and the revocation
/// endpoint. Per §Token Revocation (L2302) the revocation endpoint MUST verify the
/// caller's HTTP Message Signature and only accept revocation from an authorized
/// caller (the token issuer or a trusted PS) — deny-by-default.
/// </summary>
public class JtiStoreAndRevocationTests : IAsyncLifetime
{
    private const string ApIssuer = "http://localhost:5556";
    private const string AgentId = "aauth:revoker@ap.example";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly InMemoryJtiStore _jtiStore = new();

    private IHost? _metadataHost;
    private IHost? _host;

    public async Task InitializeAsync()
    {
        _metadataHost = await StartMetadataServer();
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    [Fact(DisplayName = "§8.5 — JTI store: first recording succeeds")]
    public async Task JtiStore_FirstRecordSucceeds()
    {
        var store = new InMemoryJtiStore();
        var result = await store.TryRecordAsync("jti-1", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.True(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: duplicate JTI is rejected (replay detection)")]
    public async Task JtiStore_DuplicateRejected()
    {
        var store = new InMemoryJtiStore();
        await store.TryRecordAsync("jti-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        var result = await store.TryRecordAsync("jti-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.False(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: revoked JTI is rejected on record")]
    public async Task JtiStore_RevokedJtiRejected()
    {
        var store = new InMemoryJtiStore();
        await store.RevokeAsync("jti-revoked");
        var result = await store.TryRecordAsync("jti-revoked", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.False(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns true for revoked tokens")]
    public async Task JtiStore_IsRevokedReturnsTrue()
    {
        var store = new InMemoryJtiStore();
        await store.RevokeAsync("jti-check");
        Assert.True(await store.IsRevokedAsync("jti-check"));
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns false for unknown tokens")]
    public async Task JtiStore_IsRevokedReturnsFalse()
    {
        var store = new InMemoryJtiStore();
        Assert.False(await store.IsRevokedAsync("unknown"));
    }

    [Fact(DisplayName = "§Token Revocation — verified + authorized caller revokes (200)")]
    public async Task Revocation_RevokesForTrustedSignedCaller()
    {
        await StartRevocationHost(o => o.TrustedRevokers = new[] { ApIssuer });

        var response = await SendSignedRevoke("jti-trusted");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync("jti-trusted"));
    }

    [Fact(DisplayName = "§Token Revocation — unsigned caller is rejected (401)")]
    public async Task Revocation_RejectsUnsignedCaller()
    {
        await StartRevocationHost(o => o.TrustedRevokers = new[] { ApIssuer });

        using var client = _host!.GetTestServer().CreateClient();
        var response = await client.PostAsJsonAsync("http://localhost/revoke", new JsonObject { ["jti"] = "jti-unsigned" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync("jti-unsigned"));
    }

    [Fact(DisplayName = "§Token Revocation — verified but untrusted caller is rejected (403)")]
    public async Task Revocation_RejectsUntrustedCaller()
    {
        // Caller's verified identity (ApIssuer) is NOT in the allow-list.
        await StartRevocationHost(o => o.TrustedRevokers = new[] { "https://some-other-ps.example" });

        var response = await SendSignedRevoke("jti-untrusted");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync("jti-untrusted"));
    }

    [Fact(DisplayName = "§Token Revocation — deny-by-default when no revokers configured (403)")]
    public async Task Revocation_DeniesByDefault()
    {
        await StartRevocationHost(configure: null); // no TrustedRevokers / predicate

        var response = await SendSignedRevoke("jti-default-deny");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — predicate can authorize a verified caller (200)")]
    public async Task Revocation_RevokesWhenPredicateAuthorizes()
    {
        await StartRevocationHost(o => o.IsTrustedRevoker = id => id == ApIssuer);

        var response = await SendSignedRevoke("jti-predicate");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync("jti-predicate"));
    }

    [Fact(DisplayName = "§Token Revocation — missing 'jti' in body is rejected (400)")]
    public async Task Revocation_RejectsMissingJti()
    {
        await StartRevocationHost(o => o.TrustedRevokers = new[] { ApIssuer });

        var response = await SendSignedRevoke(jti: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — non-JSON Content-Type is rejected (400, not 500)")]
    public async Task Revocation_RejectsNonJsonContentType()
    {
        await StartRevocationHost(o => o.TrustedRevokers = new[] { ApIssuer });

        // Verified + authorized caller, but a non-JSON body: ReadFromJsonAsync
        // throws InvalidOperationException, which must surface as 400, not 500.
        var response = await PostSignedRevoke(
            new StringContent("jti=x", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ── Helpers ──────────────────────────────────────────────────

    private async Task StartRevocationHost(Action<AAuthRevocationOptions>? configure)
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>()));
        var app = builder.Build();

        app.UseAAuthVerification(new AAuthVerificationOptions { RequireIssuerVerification = true });
        app.MapAAuthRevocationEndpoint(_jtiStore, configure);
        await app.StartAsync();
        _host = app;
    }

    private Task<HttpResponseMessage> SendSignedRevoke(string? jti)
    {
        var body = jti is null ? new JsonObject() : new JsonObject { ["jti"] = jti };
        return PostSignedRevoke(JsonContent.Create(body));
    }

    private async Task<HttpResponseMessage> PostSignedRevoke(HttpContent content)
    {
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = _apKey,
            KeyId = "ap-key-1",
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
        }.Build();

        var provider = new JwtSignatureKeyProvider(() => agentToken);
        var signing = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = _host!.GetTestServer().CreateHandler(),
        };
        using var client = new HttpClient(signing) { BaseAddress = new Uri("http://localhost") };
        return await client.PostAsync("/revoke", content);
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

        app.MapGet("/.well-known/ap-jwks.json", () =>
        {
            var jwk = _apKey.ToPublicJwk();
            jwk["kid"] = "ap-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        await app.StartAsync();
        return app;
    }
}
