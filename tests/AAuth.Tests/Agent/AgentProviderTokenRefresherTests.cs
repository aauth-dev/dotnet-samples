using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Tests.Agent;

public class AgentProviderTokenRefresherTests
{
    [Fact]
    public void Constructor_ThrowsOnNullHttp()
    {
        var keyStore = new InMemoryKeyStore();
        Assert.Throws<ArgumentNullException>(() =>
            new AgentProviderTokenRefresher(null!, keyStore, "https://ap.example/refresh", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnNullKeyStore()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AgentProviderTokenRefresher(new HttpClient(), null!, "https://ap.example/refresh", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyEndpoint()
    {
        var keyStore = new InMemoryKeyStore();
        Assert.Throws<ArgumentException>(() =>
            new AgentProviderTokenRefresher(new HttpClient(), keyStore, "", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyLocalKeyHandle()
    {
        var keyStore = new InMemoryKeyStore();
        Assert.Throws<ArgumentException>(() =>
            new AgentProviderTokenRefresher(new HttpClient(), keyStore, "https://ap.example/refresh", ""));
    }

    [Fact]
    public async Task RefreshAsync_ThrowsOnNullContext()
    {
        var keyStore = new InMemoryKeyStore();
        var refresher = new AgentProviderTokenRefresher(new HttpClient(), keyStore, "https://ap.example/refresh", "k1");
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            refresher.RefreshAsync(null!, CancellationToken.None));
    }

    [Fact]
    public async Task RefreshAsync_DelegatesToAgentProviderClient()
    {
        // AgentProviderClient.RefreshCoreAsync creates its own internal HttpClient
        // for the signed refresh request, so we verify the refresher is correctly
        // wired by checking it loads the key and attempts the refresh.
        var key = AAuthKey.Generate();
        var keyStore = new InMemoryKeyStore();
        await keyStore.StoreAsync("k1", key);

        var http = new HttpClient();
        var refresher = new AgentProviderTokenRefresher(http, keyStore, "https://ap.example/refresh", "k1");

        var context = new TokenRefreshContext
        {
            CurrentToken = "old-token",
            Issuer = "https://ap.example",
            AgentId = "aauth:test@example.com",
            SigningKeyThumbprint = "thumbprint-not-used",
        };

        // The refresh will fail at the network layer (no real AP), but it proves
        // the refresher correctly resolves the key and calls through.
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            refresher.RefreshAsync(context, CancellationToken.None));
        Assert.NotNull(ex);
    }

    [Fact]
    public async Task RefreshAsync_ThrowsWhenKeyNotFound()
    {
        var keyStore = new InMemoryKeyStore(); // empty store
        var http = new HttpClient();
        var refresher = new AgentProviderTokenRefresher(http, keyStore, "https://ap.example/refresh", "missing-key");

        var context = new TokenRefreshContext
        {
            CurrentToken = "old-token",
            Issuer = "https://ap.example",
            AgentId = "aauth:test@example.com",
            SigningKeyThumbprint = "thumbprint-not-used",
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            refresher.RefreshAsync(context, CancellationToken.None));
    }
}
