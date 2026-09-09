using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using Xunit;

namespace AAuth.Tests.Discovery;

public class DiscoveryCacheSecurityTests
{
    private static readonly Uri Address = new("https://issuer.example/jwks");

    [Fact]
    public async Task IssuerFloorSerializesDifferentColdUrls()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new Handler(() => { entered.TrySetResult(); return release.Task; });
        var client = Create(handler);
        var first = client.ResolveKeyAsync(Address, "key", "https://issuer.example");
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Assert.ThrowsAsync<HttpRequestException>(() =>
            client.ResolveKeyAsync(new Uri("https://issuer.example/keys-" + index), "key", "https://issuer.example"))));
        Assert.Equal(1, handler.Calls);
        release.SetResult("{\"keys\":[]}");
        Assert.Null(await first);
    }

    [Fact]
    public async Task IssuerFailuresBackOffAcrossUrlChangesAndCacheInvalidation()
    {
        var time = DateTimeOffset.UtcNow;
        var handler = new Handler(() => throw new HttpRequestException("offline"));
        var client = Create(handler, () => time);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key", "https://issuer.example"));
        time = time.AddSeconds(61);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ForceRefreshKeyAsync(new Uri("https://issuer.example/second"), "key", "https://issuer.example"));
        time = time.AddSeconds(61);
        client.ClearCache();
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(new Uri("https://issuer.example/third"), "key", "https://issuer.example"));
        Assert.Equal(2, handler.Calls);
        time = time.AddSeconds(60);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(new Uri("https://issuer.example/third"), "key", "https://issuer.example"));
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task DirectUrlsRemainIndependentButShareTheirFloorWithDiscoveredUrls()
    {
        var handler = new Handler(() => Task.FromResult("{\"keys\":[]}"));
        var client = Create(handler);
        await client.ResolveKeyAsync(Address, "key", "https://issuer.example");
        await client.ForceRefreshKeyAsync(Address, "key");
        var second = new Uri("https://issuer.example/second");
        await client.ResolveKeyAsync(second, "key");
        await client.ForceRefreshKeyAsync(second, "key", "https://issuer.example");
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task CapacityPressureCannotEvictIssuerFloorAfterUriBecomesEvictable()
    {
        var time = DateTimeOffset.UtcNow;
        var handler = new Handler(() => Task.FromResult("{\"keys\":[]}"));
        var client = Create(handler, () => time, capacity: 2);
        await client.ResolveKeyAsync(Address, "key", "https://issuer.example");
        time = time.AddSeconds(61);
        await client.ResolveKeyAsync(new Uri("https://issuer.example/second"), "key", "https://issuer.example");
        await client.ResolveKeyAsync(new Uri("https://other.example/keys"), "key", "https://other.example");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key", "https://issuer.example"));
        Assert.Equal(3, handler.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ParallelColdRequestsShareSuccessAndFailure(bool fail)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new Handler(async () =>
        {
            entered.TrySetResult();
            await release.Task;
            if (fail) throw new HttpRequestException("offline");
            return "{\"keys\":[]}";
        });
        var client = Create(handler);
        var requests = Enumerable.Range(0, 32).Select(async index =>
        {
            if (fail) await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key-" + index));
            else Assert.Null(await client.ResolveKeyAsync(Address, "key-" + index));
        }).ToArray();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, handler.Calls);
        release.SetResult();
        await Task.WhenAll(requests);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task CancelledWaiterDoesNotCancelSharedFetch()
    {
        var release = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new Handler(() => release.Task);
        var client = Create(handler);
        using var cancellation = new CancellationTokenSource();
        var abandoned = client.ResolveKeyAsync(Address, "key", cancellation.Token);
        var surviving = client.ResolveKeyAsync(Address, "key");
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoned);
        release.SetResult("{\"keys\":[]}");
        Assert.Null(await surviving);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task FailedRefreshReturnsStaleOnlyBeforeHardMaximumAge()
    {
        var time = DateTimeOffset.UtcNow;
        var key = AAuthKey.Generate();
        var jwk = key.ToPublicJwk();
        jwk["kid"] = "key";
        var fail = false;
        var handler = new Handler(() => fail ? throw new HttpRequestException("offline")
            : Task.FromResult(new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString()));
        var client = Create(handler, () => time, ttl: TimeSpan.FromSeconds(1));
        var first = await client.ResolveKeyAsync(Address, "key");
        fail = true;
        time = time.AddMinutes(1);
        var stale = await client.ResolveKeyAsync(Address, "key");
        Assert.Equal(first!.ComputeJwkThumbprint(), stale!.ComputeJwkThumbprint());
        Assert.Equal(2, handler.Calls);
        time = time.AddHours(24);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key"));
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task FailedAttemptsBackOffAcrossResolveAndForcedRefresh()
    {
        var time = DateTimeOffset.UtcNow;
        var handler = new Handler(() => throw new HttpRequestException("offline"));
        var client = Create(handler, () => time);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key"));
        time = time.AddMinutes(1);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ForceRefreshKeyAsync(Address, "key"));
        time = time.AddMinutes(1);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key"));
        Assert.Equal(2, handler.Calls);
        time = time.AddMinutes(1);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key"));
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task CapacityCannotEvictProtectedAttemptState()
    {
        var time = DateTimeOffset.UtcNow;
        var handler = new Handler(() => Task.FromResult("{\"keys\":[]}"));
        var client = Create(handler, () => time, capacity: 2);
        await client.ResolveKeyAsync(Address, "key");
        await client.ResolveKeyAsync(new Uri("https://issuer.example/second"), "key");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(new Uri("https://issuer.example/third"), "key"));
        await client.ResolveKeyAsync(Address, "key");
        Assert.Equal(2, handler.Calls);
        time = time.AddMinutes(1);
        await client.ResolveKeyAsync(new Uri("https://issuer.example/third"), "key");
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task ClearingCacheDoesNotClearAttemptFloor()
    {
        var handler = new Handler(() => Task.FromResult("{\"keys\":[]}"));
        var client = Create(handler);
        await client.ResolveKeyAsync(Address, "key");
        client.ClearCache();
        await Assert.ThrowsAsync<HttpRequestException>(() => client.ResolveKeyAsync(Address, "key"));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task EquivalentUriPathsShareTheSameAttemptFloor()
    {
        var handler = new Handler(() => Task.FromResult("{\"keys\":[]}"));
        var client = Create(handler);
        await client.ResolveKeyAsync(Address, "key");
        await client.ResolveKeyAsync(new Uri("https://issuer.example/nested/../jwks"), "key");
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public void SubMinuteFloorAndExcessiveHardAgeAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new JwksClient(minRefreshInterval: TimeSpan.FromSeconds(59)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new JwksClient(maxCacheAge: TimeSpan.FromHours(25)));
    }

    private static JwksClient Create(Handler handler, Func<DateTimeOffset>? clock = null,
        TimeSpan? ttl = null, int capacity = 1024) => new(new HttpClient(handler), clock: clock,
            cacheTtl: ttl, maxCacheEntries: capacity, transportContract: AAuthTransportContract.InProcessOnly);

    private sealed class Handler(Func<Task<string>> body) : HttpMessageHandler
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return new(HttpStatusCode.OK) { Content = new StringContent(await body()) };
        }
    }
}