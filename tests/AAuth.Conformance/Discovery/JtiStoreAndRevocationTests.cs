using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance tests for JTI store (replay detection) and revocation endpoint.
/// </summary>
public class JtiStoreAndRevocationTests : IAsyncLifetime
{
    private IHost? _host;
    private InMemoryJtiStore _jtiStore = new();

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapAAuthRevocationEndpoint(_jtiStore);
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
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

    [Fact(DisplayName = "§8.5 — revocation endpoint returns 200 for valid token")]
    public async Task RevocationEndpoint_Returns200()
    {
        using var client = _host!.GetTestServer().CreateClient();
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("token", "test-jti-1")
        });
        var response = await client.PostAsync("http://localhost/revoke", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§8.5 — revocation endpoint marks token as revoked in store")]
    public async Task RevocationEndpoint_MarksAsRevoked()
    {
        using var client = _host!.GetTestServer().CreateClient();
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("token", "test-jti-2")
        });
        await client.PostAsync("http://localhost/revoke", content);
        Assert.True(await _jtiStore.IsRevokedAsync("test-jti-2"));
    }

    [Fact(DisplayName = "§8.5 — revocation endpoint returns 200 even for unknown token")]
    public async Task RevocationEndpoint_Returns200ForUnknown()
    {
        using var client = _host!.GetTestServer().CreateClient();
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("token", "nonexistent")
        });
        var response = await client.PostAsync("http://localhost/revoke", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§8.5 — revocation endpoint returns 400 without token parameter")]
    public async Task RevocationEndpoint_Returns400WithoutToken()
    {
        using var client = _host!.GetTestServer().CreateClient();
        var content = new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>());
        var response = await client.PostAsync("http://localhost/revoke", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
