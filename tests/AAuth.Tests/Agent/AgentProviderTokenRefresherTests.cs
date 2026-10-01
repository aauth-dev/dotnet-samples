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
    public async Task RefreshAsync_DelegatesToSingleKeyAdmittedClient()
    {
        var key = AAuthKey.Generate();
        var keyStore = new InMemoryKeyStore();
        await keyStore.StoreAsync("k1", key);

        var transport = new RefreshTransport();
        using var http = new InProcessHttpClient(transport);
        var refresher = new AgentProviderTokenRefresher(http, keyStore, "https://ap.example/refresh", "k1");

        var context = new TokenRefreshContext
        {
            CurrentToken = "old-token",
            Issuer = "https://ap.example",
            AgentId = "aauth:test@example.com",
            SigningKeyThumbprint = "thumbprint-not-used",
        };

        Assert.Equal("new-token", await refresher.RefreshAsync(context, CancellationToken.None));
        Assert.StartsWith("sig=hwk", transport.SignatureKey);
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public void AutomaticTwoKeyRefreshSurface_IsRemoved()
    {
        Assert.Null(Type.GetType("AAuth.Agent.RefreshMode, AAuth"));
        Assert.DoesNotContain(typeof(AgentProviderTokenRefresher).GetConstructors(),
            ctor => ctor.GetParameters().Any(parameter => parameter.ParameterType.Name == "RefreshMode"));
        Assert.Null(typeof(AgentProviderTokenRefresher).GetProperty("LatestEphemeralKey"));
        Assert.Null(typeof(AgentProviderTokenRefresher.RefresherBuilder).GetMethod("WithRefreshMode"));
    }

    [Fact]
    public async Task RefreshAsync_RejectsUnregisteredTransport()
    {
        var keyStore = new InMemoryKeyStore();
        await keyStore.StoreAsync("key", AAuthKey.Generate());
        var transport = new RefreshTransport();
        using var http = new HttpClient(transport);
        var client = new AgentProviderClient(http, keyStore);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.RefreshAsync("https://ap.example/refresh", "key"));
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task RefreshAsync_CancellationDoesNotSend()
    {
        var keyStore = new InMemoryKeyStore();
        await keyStore.StoreAsync("key", AAuthKey.Generate());
        var transport = new RefreshTransport();
        using var http = new InProcessHttpClient(transport);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var client = new AgentProviderClient(http, keyStore);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.RefreshAsync("https://ap.example/refresh", "key", cancellation.Token));
        Assert.Equal(0, transport.Calls);
    }

    private sealed class RefreshTransport : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? SignatureKey { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            SignatureKey = string.Join("", request.Headers.GetValues("Signature-Key"));
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"agent_token\":\"new-token\"}"),
            });
        }
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
