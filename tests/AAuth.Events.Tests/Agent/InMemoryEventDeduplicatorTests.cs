using System.Collections.Concurrent;
using AAuth.Events.Agent;

namespace AAuth.Events.Tests.Agent;

public sealed class InMemoryEventDeduplicatorTests
{
    [Fact]
    public async Task ConcurrentRecordingIsAtomic()
    {
        var deduplicator = new InMemoryEventDeduplicator(capacity: 8);
        var results = new ConcurrentBag<bool>();
        await Task.WhenAll(Enumerable.Range(0, 64).Select(async _ =>
            results.Add(await deduplicator.TryRecordAsync("same-key"))));

        Assert.Single(results, static result => result);
        Assert.Equal(1, deduplicator.Count);
    }

    [Fact]
    public async Task CapacityAndExpiryAreDeterministic()
    {
        var clock = new TestClock(DateTimeOffset.UnixEpoch);
        var deduplicator = new InMemoryEventDeduplicator(
            capacity: 2,
            retention: TimeSpan.FromMinutes(1),
            clock: clock.GetUtcNow);

        Assert.True(await deduplicator.TryRecordAsync("first"));
        Assert.True(await deduplicator.TryRecordAsync("second"));
        Assert.True(await deduplicator.TryRecordAsync("third"));
        Assert.True(await deduplicator.TryRecordAsync("first"));
        Assert.False(await deduplicator.TryRecordAsync("third"));
        Assert.Equal(2, deduplicator.Count);

        clock.Now = clock.Now.AddMinutes(1);
        Assert.Equal(0, deduplicator.Count);
        Assert.True(await deduplicator.TryRecordAsync("first"));
    }

    [Fact]
    public async Task CancellationIsObserved()
    {
        var deduplicator = new InMemoryEventDeduplicator();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            deduplicator.TryRecordAsync("key", cancellation.Token).AsTask());
    }

    private sealed class TestClock
    {
        public TestClock(DateTimeOffset now) => Now = now;
        public DateTimeOffset Now { get; set; }
        public DateTimeOffset GetUtcNow() => Now;
    }
}
