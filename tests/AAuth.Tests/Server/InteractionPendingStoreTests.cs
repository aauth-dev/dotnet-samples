using System;
using System.Linq;
using System.Threading.Tasks;
using AAuth.Server;
using Xunit;

namespace AAuth.Tests.Server;

public class InteractionPendingStoreTests
{
    [Fact]
    public void Park_ThenGet_ReturnsEntry()
    {
        var store = new InMemoryInteractionPendingStore();
        var entry = store.Park("inbox.read", "jkt-1", TimeSpan.FromMinutes(5));
        Assert.NotNull(store.Get(entry.Code));
        Assert.Equal("inbox.read", store.Get(entry.Code)!.Scope);
    }

    [Fact]
    public void TryConsume_OnlyAfterApproval()
    {
        var store = new InMemoryInteractionPendingStore();
        var entry = store.Park("inbox.read", "jkt-1", TimeSpan.FromMinutes(5));

        // Not approved yet → not consumable, and the entry survives.
        Assert.False(store.TryConsume(entry.Code, out _));
        Assert.NotNull(store.Get(entry.Code));

        store.Approve(entry.Code);
        Assert.True(store.TryConsume(entry.Code, out var consumed));
        Assert.Equal("jkt-1", consumed.AgentJkt);

        // Single-use: a second consume finds nothing.
        Assert.False(store.TryConsume(entry.Code, out _));
        Assert.Null(store.Get(entry.Code));
    }

    [Fact]
    public void Get_ExpiredEntry_ReturnsNull()
    {
        var store = new InMemoryInteractionPendingStore();
        var entry = store.Park("inbox.read", "jkt-1", TimeSpan.FromMilliseconds(-1));
        Assert.Null(store.Get(entry.Code));
    }

    [Fact]
    public async Task TryConsume_ConcurrentPolls_IssueExactlyOnce()
    {
        var store = new InMemoryInteractionPendingStore();
        var entry = store.Park("inbox.read", "jkt-1", TimeSpan.FromMinutes(5));
        store.Approve(entry.Code);

        // 50 concurrent consumers race; exactly one may win.
        var tasks = Enumerable.Range(0, 50)
            .Select(i => Task.Run(() => store.TryConsume(entry.Code, out _)))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, results.Count(won => won));
    }
}
