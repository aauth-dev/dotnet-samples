using System;
using System.Threading.Tasks;
using AAuth.Server;
using Xunit;

namespace AAuth.Conformance.Discovery;

public class TokenInventoryTests
{
    [Fact]
    public async Task SameIdFromTwoIssuers_IsolatedIncludingGrants()
    {
        var store = new InMemoryJtiStore();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var first = new TokenKey("https://first.example", "same-id");
        var second = new TokenKey("https://second.example", "same-id");
        await store.RegisterAsync(first, expiry);
        await store.RegisterAsync(second, expiry);
        var firstGrant = new TokenGrant(new TokenKey("https://ps.example", "first"), "https://r1.example", expiry);
        var secondGrant = new TokenGrant(new TokenKey("https://as.example", "second"), "https://r2.example", expiry);
        Assert.True(await store.RegisterGrantAsync([first], firstGrant));
        Assert.True(await store.RegisterGrantAsync([second], secondGrant));

        Assert.True(await store.RevokeAsync(first));

        Assert.True(await store.IsRevokedAsync(first));
        Assert.False(await store.IsRevokedAsync(second));
        Assert.True(await store.RegisterAsync(second, expiry));
        Assert.Equal(firstGrant, Assert.Single(await store.GetGrantsAsync(first)));
        Assert.Equal(secondGrant, Assert.Single(await store.GetGrantsAsync(second)));
        Assert.False(await store.RegisterGrantAsync([first], firstGrant));
        Assert.True(await store.RegisterGrantAsync([second], secondGrant));
    }

    [Fact]
    public async Task MissingOrRevokedSource_CannotCreateGrant()
    {
        var store = new InMemoryJtiStore();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var source = new TokenKey("https://ap.example", "source");
        var grant = new TokenGrant(new TokenKey("https://ps.example", "grant"), "https://r.example", expiry);
        Assert.False(await store.RegisterGrantAsync([source], grant));
        Assert.False(await store.RevokeAsync(grant.Token));
        await store.RegisterAsync(source, expiry);
        await store.RevokeAsync(source);
        Assert.False(await store.RegisterGrantAsync([source], grant));
        Assert.Empty(await store.GetGrantsAsync(source));
    }

    [Fact]
    public async Task ExpiredKnownToken_RemainsIdempotentUntilBoundedCleanup()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, retention: TimeSpan.FromMinutes(1));
        var token = new TokenKey("https://issuer.example", "token");
        await store.RegisterAsync(token, clock.GetUtcNow().AddSeconds(1));
        clock.Now = clock.Now.AddSeconds(2);
        Assert.True(await store.RevokeAsync(token));
        Assert.True(await store.RevokeAsync(token));
        clock.Now = clock.Now.AddMinutes(2);
        store.Cleanup();
        Assert.False(await store.RevokeAsync(token));
        Assert.False(await store.IsRevokedAsync(token));
    }

    [Fact]
    public async Task CapacityFailsClosedWithoutEvictingActiveRevocation()
    {
        var store = new InMemoryJtiStore(capacity: 1);
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var token = new TokenKey("https://issuer.example", "token");
        await store.RegisterAsync(token, expiry);
        await store.RevokeAsync(token);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.RegisterAsync(new TokenKey("https://other.example", "token"), expiry));
        Assert.True(await store.IsRevokedAsync(token));
    }

    private sealed class MutableClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}