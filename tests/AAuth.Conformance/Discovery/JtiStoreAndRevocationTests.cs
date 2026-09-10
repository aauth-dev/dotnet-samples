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
        var result = await store.TryRecordRequestAsync("request-1", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.True(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: duplicate JTI is rejected (replay detection)")]
    public async Task JtiStore_DuplicateRejected()
    {
        var store = new InMemoryJtiStore();
        await store.TryRecordRequestAsync("request-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        var result = await store.TryRecordRequestAsync("request-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.False(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: revoked JTI is rejected on record")]
    public async Task JtiStore_RevokedJtiRejected()
    {
        var store = new InMemoryJtiStore();
        var token = new TokenKey(ApIssuer, "jti-revoked");
        var expiration = DateTimeOffset.UtcNow.AddMinutes(5);
        await store.RegisterAsync(token, expiration);
        Assert.True(await store.RevokeAsync(token));
        var result = await store.RegisterAsync(token, expiration);
        Assert.False(result);
        Assert.True(await store.TryRecordRequestAsync(token.TokenId, expiration));
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns true for revoked tokens")]
    public async Task JtiStore_IsRevokedReturnsTrue()
    {
        var store = new InMemoryJtiStore();
        var token = new TokenKey(ApIssuer, "jti-check");
        await store.RegisterAsync(token, DateTimeOffset.UtcNow.AddMinutes(5));
        await store.RevokeAsync(token);
        Assert.True(await store.IsRevokedAsync(token));
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns false for unknown tokens")]
    public async Task JtiStore_IsRevokedReturnsFalse()
    {
        var store = new InMemoryJtiStore();
        Assert.False(await store.IsRevokedAsync(new TokenKey(ApIssuer, "unknown")));
        Assert.False(await store.RevokeAsync(new TokenKey(ApIssuer, "unknown")));
    }

    [Fact(DisplayName = "§Token Revocation — verified + authorized caller revokes (200)")]
    public async Task Revocation_RevokesForTrustedSignedCaller()
    {
        await StartRevocationHost(o => o.AllowTokenIssuer = true);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-trusted"), FixedClock.AddMinutes(5));

        var response = await SendSignedRevoke("jti-trusted");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-trusted")));
    }

    [Fact(DisplayName = "§Token Revocation — unsigned caller is rejected (401)")]
    public async Task Revocation_RejectsUnsignedCaller()
    {
        await StartRevocationHost(o => o.AllowTokenIssuer = true);

        using var client = _host!.GetTestServer().CreateClient();
        var response = await client.PostAsJsonAsync("http://localhost/revoke", new JsonObject { ["jti"] = "jti-unsigned" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-unsigned")));
    }

    [Fact(DisplayName = "§Token Revocation — verified but untrusted caller is rejected (403)")]
    public async Task Revocation_RejectsUntrustedCaller()
    {
        // Caller's verified identity (ApIssuer) is NOT in the allow-list.
        await StartRevocationHost(o => o.TrustedPersonServers = new[] { "https://some-other-ps.example" });

        var response = await SendSignedRevoke("jti-untrusted");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_revoker", (string?)body!["error"]);
        Assert.Contains("not authorized", (string?)body["detail"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-untrusted")));
    }

    [Fact(DisplayName = "§Token Revocation — deny-by-default when no revokers configured (403)")]
    public async Task Revocation_DeniesByDefault()
    {
        await StartRevocationHost(configure: null);

        var response = await SendSignedRevoke("jti-default-deny");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — predicate can authorize a verified caller (200)")]
    public async Task Revocation_RevokesWhenPredicateAuthorizes()
    {
        await StartRevocationHost(o => o.IsTrustedPersonServer = (id, token) => id == ApIssuer && token.Issuer == ApIssuer);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-predicate"), FixedClock.AddMinutes(5));

        var response = await SendSignedRevoke("jti-predicate");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-predicate")));
    }

    [Fact(DisplayName = "§Token Revocation — missing 'jti' in body is rejected (400)")]
    public async Task Revocation_RejectsMissingJti()
    {
        await StartRevocationHost(o => o.AllowTokenIssuer = true);

        var response = await SendSignedRevoke(jti: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Contains("'jti' string", (string?)body["detail"]);
    }

    [Fact(DisplayName = "§Token Revocation — non-JSON Content-Type is rejected (400, not 500)")]
    public async Task Revocation_RejectsNonJsonContentType()
    {
        await StartRevocationHost(o => o.AllowTokenIssuer = true);

        // Verified + authorized caller, but a non-JSON body: ReadFromJsonAsync
        // throws InvalidOperationException, which must surface as 400, not 500.
        var response = await PostSignedRevoke(
            new StringContent("jti=x", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_WithoutVerification_ReturnsProblemDetails()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapAAuthRevocationEndpoint(_jtiStore);
        await app.StartAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsJsonAsync("/revoke", new { jti = "unverified" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", body!["error"]!.GetValue<string>());
        Assert.Contains("verified AAuth signature", body["detail"]!.GetValue<string>());
        Assert.False(body.ContainsKey("error_description"));
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "unverified")));
    }

    [Fact]
    public async Task Revocation_RejectsMissingIssuer()
    {
        await StartRevocationHost(options => options.AllowTokenIssuer = true);

        var response = await PostSignedRevoke(JsonContent.Create(new { jti = "missing-issuer" }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_AgentCannotImpersonateItsProvider()
    {
        await StartRevocationHost(options => options.AllowTokenIssuer = true);

        var response = await PostSignedRevoke(JsonContent.Create(new { iss = ApIssuer, jti = "provider-token" }), asAgent: true);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_Unknown404_KnownRepeated200()
    {
        await StartRevocationHost(options => options.AllowTokenIssuer = true);
        Assert.Equal(HttpStatusCode.NotFound, (await SendSignedRevoke("unknown")).StatusCode);
        var token = new TokenKey(ApIssuer, "known");
        await _jtiStore.RegisterAsync(token, FixedClock.AddMinutes(5));
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("known")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("known")).StatusCode);
    }

    [Fact]
    public async Task Revocation_IssuerCannotRevokeOtherIssuerWithSameId()
    {
        await StartRevocationHost(options => options.AllowTokenIssuer = true);
        var own = new TokenKey(ApIssuer, "shared");
        var other = new TokenKey("https://other.example", "shared");
        await _jtiStore.RegisterAsync(own, FixedClock.AddMinutes(5));
        await _jtiStore.RegisterAsync(other, FixedClock.AddMinutes(5));

        var response = await PostSignedRevoke(JsonContent.Create(new { iss = other.Issuer, jti = other.TokenId }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync(other));
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("shared")).StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(own));
        Assert.False(await _jtiStore.IsRevokedAsync(other));
    }

    [Theory]
    [InlineData("{\"iss\":1,\"jti\":\"id\"}")]
    [InlineData("{\"iss\":\"https://issuer.example\",\"jti\":[]}")]
    [InlineData("{\"iss\":\"\",\"jti\":\"id\"}")]
    [InlineData("{\"iss\":\"https://issuer.example\",\"jti\":\" \"}")]
    public async Task Revocation_RejectsMalformedPair(string json)
    {
        await StartRevocationHost(options => options.AllowTokenIssuer = true);
        var response = await PostSignedRevoke(new StringContent(json, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_CascadesExactRecords_AndReportsMissingDelivery()
    {
        var first = new TokenKey(ApIssuer, "cascade");
        var other = new TokenKey("https://other.example", "cascade");
        var expiry = FixedClock.AddMinutes(5);
        await _jtiStore.RegisterAsync(first, expiry);
        await _jtiStore.RegisterAsync(other, expiry);
        var grant = new TokenGrant(new TokenKey("https://ps.example", "provided"), "https://r.example", expiry);
        var foreign = new TokenGrant(new TokenKey("https://as.example", "provided"), "https://other-r.example", expiry);
        await _jtiStore.RegisterGrantAsync([first], grant);
        await _jtiStore.RegisterGrantAsync([other], foreign);
        await StartRevocationHost(options => options.AllowTokenIssuer = true);

        Assert.Equal(HttpStatusCode.BadGateway, (await SendSignedRevoke(first.TokenId)).StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(first));
        Assert.False(await _jtiStore.IsRevokedAsync(other));
        Assert.False(await _jtiStore.IsRevokedAsync(foreign.Token));
        var delivered = new System.Collections.Generic.List<TokenGrant>();
        await StartRevocationHost(options =>
        {
            options.AllowTokenIssuer = true;
            options.RevokeGrantAsync = (record, _) =>
            {
                delivered.Add(record);
                return Task.FromResult(true);
            };
        });
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke(first.TokenId)).StatusCode);
        Assert.Equal(grant, Assert.Single(delivered));
    }

    // ── Helpers ──────────────────────────────────────────────────

    private async Task StartRevocationHost(Action<AAuthRevocationOptions>? configure)
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>(),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>(),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        var app = builder.Build();

        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            EgressPolicy = TestEgress.Policy,
            AcceptedSchemes = ["jwt", "jwks_uri"],
        });
        app.MapAAuthRevocationEndpoint(_jtiStore, configure);
        await app.StartAsync();
        _host = app;
    }

    private Task<HttpResponseMessage> SendSignedRevoke(string? jti)
    {
        var body = new JsonObject { ["iss"] = ApIssuer };
        if (jti is not null) body["jti"] = jti;
        return PostSignedRevoke(JsonContent.Create(body));
    }

    private async Task<HttpResponseMessage> PostSignedRevoke(HttpContent content, bool asAgent = false)
    {
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = _apKey,
            KeyId = "ap-key-1",
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
        }.Build();

        ISignatureKeyProvider provider = asAgent
            ? new JwtSignatureKeyProvider(() => agentToken)
            : new JwksUriSignatureKeyProvider(ApIssuer, "aauth-agent.json", "ap-key-1");
        var signing = new AAuthSigningHandler(asAgent ? _agentKey : _apKey, provider, () => FixedClock)
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
