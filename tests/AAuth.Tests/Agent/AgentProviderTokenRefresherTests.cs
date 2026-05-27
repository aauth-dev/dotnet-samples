using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class AgentProviderTokenRefresherTests
{
    [Fact]
    public void Constructor_ThrowsOnNullHttp()
    {
        var keyStore = new InMemoryKeyStore();
        Assert.Throws<ArgumentNullException>(() =>
            new AgentProviderTokenRefresher(null!, keyStore, "https://ap.example/refresh"));
    }

    [Fact]
    public void Constructor_ThrowsOnNullKeyStore()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AgentProviderTokenRefresher(new HttpClient(), null!, "https://ap.example/refresh"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyEndpoint()
    {
        var keyStore = new InMemoryKeyStore();
        Assert.Throws<ArgumentException>(() =>
            new AgentProviderTokenRefresher(new HttpClient(), keyStore, ""));
    }

    [Fact]
    public async Task RefreshAsync_ThrowsOnNullContext()
    {
        var keyStore = new InMemoryKeyStore();
        var refresher = new AgentProviderTokenRefresher(new HttpClient(), keyStore, "https://ap.example/refresh");
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
        var refresher = new AgentProviderTokenRefresher(http, keyStore, "https://ap.example/refresh");

        var context = new TokenRefreshContext
        {
            CurrentToken = "old-token",
            Issuer = "https://ap.example",
            AgentId = "aauth:test@example.com",
            KeyId = "k1",
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
        var refresher = new AgentProviderTokenRefresher(http, keyStore, "https://ap.example/refresh");

        var context = new TokenRefreshContext
        {
            CurrentToken = "old-token",
            Issuer = "https://ap.example",
            AgentId = "aauth:test@example.com",
            KeyId = "missing-key",
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            refresher.RefreshAsync(context, CancellationToken.None));
    }

    private sealed class MockApHandler : HttpMessageHandler
    {
        private readonly string _token;
        public bool WasCalled { get; private set; }

        public MockApHandler(string token) => _token = token;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            WasCalled = true;
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $"{{\"agent_token\":\"{_token}\",\"token_type\":\"agent\"}}",
                    System.Text.Encoding.UTF8,
                    "application/json")
            };
            return Task.FromResult(response);
        }
    }
}
