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

        await store.RevokeAsync(first, expiry);

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
        await store.RegisterAsync(source, expiry);
        await store.RevokeAsync(source, expiry);
        Assert.False(await store.RegisterGrantAsync([source], grant));
        Assert.Empty(await store.GetGrantsAsync(source));
    }

    [Fact(DisplayName = "§Token Revocation — an unseen token is recorded and refused when later presented")]
    public async Task UnseenToken_RevocationIsRecordedAndRefusesLaterRegistration()
    {
        var store = new InMemoryJtiStore();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var unseen = new TokenKey("https://ps.example", "never-presented");
        var sameIdOtherIssuer = new TokenKey("https://other.example", "never-presented");

        await store.RevokeAsync(unseen, expiry);
        await store.RevokeAsync(unseen, expiry);

        Assert.True(await store.IsRevokedAsync(unseen));
        Assert.False(await store.RegisterAsync(unseen, expiry));
        Assert.False(await store.RegisterGrantAsync([unseen], new TokenGrant(new TokenKey("https://as.example", "child"), "https://r.example", expiry)));
        Assert.False(await store.IsRevokedAsync(sameIdOtherIssuer));
        Assert.True(await store.RegisterAsync(sameIdOtherIssuer, expiry));
    }

    [Fact]
    public async Task UnseenRevocation_IsRetainedUntilItsExpiryPlusRetention()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, retention: TimeSpan.FromMinutes(1));
        var token = new TokenKey("https://issuer.example", "unseen");
        await store.RevokeAsync(token, clock.GetUtcNow().AddMinutes(2));
        clock.Now = clock.Now.AddMinutes(2.5);
        store.Cleanup();
        Assert.True(await store.IsRevokedAsync(token));
        clock.Now = clock.Now.AddMinutes(1);
        store.Cleanup();
        Assert.False(await store.IsRevokedAsync(token));

        var stale = new TokenKey("https://issuer.example", "stale");
        await store.RevokeAsync(stale, clock.GetUtcNow().AddMinutes(-2));
        Assert.False(await store.IsRevokedAsync(stale));
    }

    [Fact]
    public async Task ExpiredKnownToken_RemainsIdempotentUntilBoundedCleanup()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, retention: TimeSpan.FromMinutes(1));
        var token = new TokenKey("https://issuer.example", "token");
        var expiry = clock.GetUtcNow().AddSeconds(1);
        await store.RegisterAsync(token, expiry);
        clock.Now = clock.Now.AddSeconds(2);
        await store.RevokeAsync(token, expiry);
        await store.RevokeAsync(token, expiry);
        Assert.True(await store.IsRevokedAsync(token));
        clock.Now = clock.Now.AddMinutes(2);
        store.Cleanup();
        Assert.False(await store.IsRevokedAsync(token));
        await store.RevokeAsync(token, expiry);
        Assert.False(await store.IsRevokedAsync(token));
    }

    [Fact]
    public async Task CapacityFailsClosedWithoutEvictingActiveRevocation()
    {
        var store = new InMemoryJtiStore(capacity: 1);
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var token = new TokenKey("https://issuer.example", "token");
        await store.RegisterAsync(token, expiry);
        await store.RevokeAsync(token, expiry);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.RegisterAsync(new TokenKey("https://other.example", "token"), expiry));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.RevokeAsync(new TokenKey("https://other.example", "unseen"), expiry));
        Assert.True(await store.IsRevokedAsync(token));
    }

    private sealed class MutableClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}