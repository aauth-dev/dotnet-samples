using System.Collections.Concurrent;
using AAuth.Server;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Tests.Server;

// Stands in for a shared store (for example Redis SET NX): each app instance has its own
// gate object over the same backing dictionary, so waits cross instances by polling.
internal sealed class SharedStoreGate(ConcurrentDictionary<string, HeldInvocationResult?> shared) : IAAuthSingleUseGate
{
    public int Claims;

    public ValueTask<SingleUseClaim> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        if (shared.TryAdd(key, null))
        {
            Interlocked.Increment(ref Claims);
            return ValueTask.FromResult(new SingleUseClaim(true, null));
        }
        return ValueTask.FromResult(new SingleUseClaim(false, shared.TryGetValue(key, out var result) ? result : null));
    }

    public ValueTask CompleteAsync(string key, HeldInvocationResult result, CancellationToken cancellationToken = default)
    {
        shared[key] = result;
        return ValueTask.CompletedTask;
    }

    public ValueTask ReleaseAsync(string key, CancellationToken cancellationToken = default)
    {
        shared.TryRemove(key, out _);
        return ValueTask.CompletedTask;
    }

    public ValueTask<HeldInvocationResult?> GetResultAsync(string key, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(shared.TryGetValue(key, out var result) ? result : null);
}

public class SingleUseGateTests
{
    private static readonly DateTimeOffset Expiry = DateTimeOffset.UtcNow.AddMinutes(5);

    [Fact(DisplayName = "a registered custom gate replaces the in-memory default")]
    public async Task CustomGate_IsUsed()
    {
        var custom = new SharedStoreGate(new());
        var services = new ServiceCollection();
        services.AddSingleton<IAAuthSingleUseGate>(custom);
        services.AddAAuthHeldInvocations();
        await using var provider = services.BuildServiceProvider();

        var gate = provider.GetRequiredService<IAAuthSingleUseGate>();
        Assert.Same(custom, gate);
        await gate.ExecuteOnceAsync("grant-1", Expiry, _ => Task.FromResult(HeldInvocationResult.Json(new { ok = true })));
        Assert.Equal(1, custom.Claims);
    }

    [Fact(DisplayName = "the in-memory gate is registered by default")]
    public async Task InMemoryGate_IsDefault()
    {
        var services = new ServiceCollection();
        services.AddAAuthHeldInvocations();
        await using var provider = services.BuildServiceProvider();

        Assert.IsType<InMemorySingleUseGate>(provider.GetRequiredService<IAAuthSingleUseGate>());
        Assert.IsType<InMemoryHeldInvocationStore>(provider.GetRequiredService<IAAuthHeldInvocationStore>());
    }

    [Fact(DisplayName = "single use holds under concurrency and replays the retained result")]
    public async Task SingleUse_UnderConcurrency()
    {
        var gate = new InMemorySingleUseGate();
        var executions = 0;
        async Task<HeldInvocationResult> Execute(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref executions);
            await Task.Delay(20, cancellationToken);
            return HeldInvocationResult.Json(new { n = 1 });
        }

        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => gate.ExecuteOnceAsync("grant-1", Expiry, Execute)));
        var other = await gate.ExecuteOnceAsync("grant-2", Expiry, Execute);

        Assert.Equal(2, executions);
        Assert.All(results, result => Assert.Same(results[0], result));
        Assert.NotSame(results[0], other);
    }

    [Fact(DisplayName = "a failed execution releases the grant for a retry")]
    public async Task FailedExecution_Releases()
    {
        var gate = new InMemorySingleUseGate();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            gate.ExecuteOnceAsync("grant-1", Expiry, _ => throw new InvalidOperationException("boom")));

        var retried = await gate.ExecuteOnceAsync("grant-1", Expiry, _ => Task.FromResult(HeldInvocationResult.Json(new { ok = true })));
        Assert.Equal(200, retried.StatusCode);
    }

    [Fact(DisplayName = "a shared-store gate stays single-use across two app instances")]
    public async Task SharedStore_SingleUseAcrossInstances()
    {
        var shared = new ConcurrentDictionary<string, HeldInvocationResult?>();
        var executions = 0;
        async Task<HeldInvocationResult> Execute(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref executions);
            await Task.Delay(50, cancellationToken);
            return HeldInvocationResult.Json(new { booked = true });
        }

        var instances = Enumerable.Range(0, 2).Select(_ =>
        {
            var services = new ServiceCollection();
            services.AddSingleton<IAAuthSingleUseGate>(new SharedStoreGate(shared));
            services.AddAAuthHeldInvocations();
            return services.BuildServiceProvider();
        }).ToArray();
        try
        {
            var calls = instances.SelectMany(provider => Enumerable.Range(0, 8).Select(_ =>
                provider.GetRequiredService<IAAuthSingleUseGate>().ExecuteOnceAsync("grant-1", Expiry, Execute)));
            var results = await Task.WhenAll(calls);

            Assert.Equal(1, executions);
            Assert.All(results, result => Assert.Equal(results[0].Body, result.Body));
        }
        finally
        {
            foreach (var provider in instances) await provider.DisposeAsync();
        }
    }
}
