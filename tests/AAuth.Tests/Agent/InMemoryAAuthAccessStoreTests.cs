using AAuth.Agent;
using Xunit;

namespace AAuth.Tests.Agent;

public class InMemoryAAuthAccessStoreTests
{
    [Fact]
    public void SetAndTryGet_RoundTrips()
    {
        var store = new InMemoryAAuthAccessStore();
        store.Set("https://resource.example", "token-1");

        Assert.True(store.TryGet("https://resource.example", out var token));
        Assert.Equal("token-1", token);
    }

    [Fact]
    public void TryGet_MissingOrigin_ReturnsFalse()
    {
        var store = new InMemoryAAuthAccessStore();
        Assert.False(store.TryGet("https://resource.example", out var token));
        Assert.Equal(string.Empty, token);
    }

    [Fact]
    public void Set_LastWriterWins()
    {
        var store = new InMemoryAAuthAccessStore();
        store.Set("https://resource.example", "token-1");
        store.Set("https://resource.example", "token-2");

        Assert.True(store.TryGet("https://resource.example", out var token));
        Assert.Equal("token-2", token);
    }

    [Fact]
    public void Remove_DeletesToken()
    {
        var store = new InMemoryAAuthAccessStore();
        store.Set("https://resource.example", "token-1");
        store.Remove("https://resource.example");

        Assert.False(store.TryGet("https://resource.example", out _));
    }

    [Fact]
    public void DifferentOrigins_AreIsolated()
    {
        var store = new InMemoryAAuthAccessStore();
        store.Set("https://a.example", "token-a");
        store.Set("https://b.example", "token-b");

        Assert.True(store.TryGet("https://a.example", out var a));
        Assert.True(store.TryGet("https://b.example", out var b));
        Assert.Equal("token-a", a);
        Assert.Equal("token-b", b);
    }
}
