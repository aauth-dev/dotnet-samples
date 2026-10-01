using System;
using System.Threading.Tasks;
using AAuth;
using AAuth.Server;
using Microsoft.AspNetCore.Http;
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
        Assert.True(await store.ContainsTokenAsync(source));
        await store.RevokeAsync(source, expiry);
        Assert.True(await store.ContainsTokenAsync(source));
        Assert.False(await store.RegisterGrantAsync([source], grant));
        Assert.Empty(await store.GetGrantsAsync(source));
        Assert.False(await store.ContainsTokenAsync(new TokenKey("https://ap.example", "missing")));
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

    [Fact(DisplayName = "§Revocation Cascade — a cascaded descendant stays revoked until its own exp plus retention, on a controlled clock")]
    public async Task CascadedDescendant_IsRetainedOnItsOwnExpiry()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, retention: TimeSpan.FromMinutes(1));
        var root = new TokenKey("https://ps.example", "person");
        var child = new TokenKey("https://ps.example", "auth");
        var rootExpiry = clock.GetUtcNow().AddMinutes(10);
        var childExpiry = clock.GetUtcNow().AddMinutes(5);
        Assert.True(await store.RegisterAsync(root, rootExpiry));
        Assert.True(await store.RegisterGrantAsync([root], new TokenGrant(child, "https://resource.example", childExpiry)));

        await store.RevokeAsync(root, rootExpiry);
        Assert.True(await store.IsRevokedAsync(child));

        // The child outlives nothing: past its exp but inside retention it is still refused.
        clock.Now = childExpiry.AddSeconds(30);
        store.Cleanup();
        Assert.True(await store.IsRevokedAsync(child));
        Assert.True(await store.IsRevokedAsync(root));

        // Past the child's exp plus retention it is purged; the root, whose exp is later, is not.
        clock.Now = childExpiry.AddMinutes(2);
        store.Cleanup();
        Assert.False(await store.IsRevokedAsync(child));
        Assert.True(await store.IsRevokedAsync(root));
        Assert.False(await store.RegisterGrantAsync([root], new TokenGrant(new TokenKey("https://ps.example", "late"),
            "https://resource.example", rootExpiry)));
    }

    [Fact]
    public async Task Provenance_PrunesAtTokenExpiryPlusRetention()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, retention: TimeSpan.FromMinutes(1));
        var source = new TokenKey("https://ap.example", "agent");
        var binding = new TokenKey("https://ps.example", "agent-person-binding https://ap.example aauth:agent@example");
        var issued = new TokenKey("https://ps.example", "person");
        var caller = new UpstreamCallerRecord("https://ap.example", "aauth:agent@example", source, binding);
        var sourceExpiry = clock.GetUtcNow().AddMinutes(10);
        var issuedExpiry = clock.GetUtcNow().AddMinutes(1);
        await store.RegisterAsync(source, sourceExpiry);
        await store.RegisterAsync(binding, DateTimeOffset.MaxValue.AddDays(-1));
        Assert.True(await store.RegisterGrantAsync([source, binding], new TokenGrant(issued, "https://r.example", issuedExpiry)
        {
            Provenance = new AAuthTokenProvenance(AAuthConstants.TokenTypes.PersonToken,
                "https://r.example", "person-sub", "https://ps.example", caller),
        }));

        clock.Now = issuedExpiry.AddSeconds(30);
        store.Cleanup();
        Assert.NotNull((await store.GetGrantAsync(issued))?.Provenance);

        clock.Now = issuedExpiry.AddMinutes(2);
        store.Cleanup();
        Assert.Null(await store.GetGrantAsync(issued));
    }

    [Fact]
    public async Task Provenance_DistinctResourceQuotaRejectsBeforeAdditionalMint()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, provenanceResourceQuota: 1);
        var source = new TokenKey("https://ap.example", "agent");
        var binding = new TokenKey("https://ps.example", "agent-person-binding https://ap.example aauth:agent@example");
        var caller = new UpstreamCallerRecord("https://ap.example", "aauth:agent@example", source, binding);
        var expiry = clock.GetUtcNow().AddMinutes(10);
        await store.RegisterAsync(source, expiry);
        await store.RegisterAsync(binding, DateTimeOffset.MaxValue.AddDays(-1));

        Assert.True(await store.CheckProvenanceQuotaAsync(caller, "https://r1.example"));
        Assert.True(await store.RegisterGrantAsync([source, binding], new TokenGrant(
            new TokenKey("https://ps.example", "one"), "https://r1.example", expiry)
        {
            Provenance = new AAuthTokenProvenance(AAuthConstants.TokenTypes.PersonToken,
                "https://r1.example", "person-sub", "https://ps.example", caller),
        }));
        Assert.True(await store.CheckProvenanceQuotaAsync(caller, "https://r1.example"));
        Assert.False(await store.CheckProvenanceQuotaAsync(caller, "https://r2.example"));
        Assert.False(await store.RegisterGrantAsync([source, binding], new TokenGrant(
            new TokenKey("https://ps.example", "two"), "https://r2.example", expiry)
        {
            Provenance = new AAuthTokenProvenance(AAuthConstants.TokenTypes.PersonToken,
                "https://r2.example", "person-sub", "https://ps.example", caller),
        }));
    }

    [Fact]
    public async Task Provenance_QuotaBreachReturns429BeforeMinting()
    {
        var clock = new MutableClock();
        var store = new InMemoryJtiStore(clock, provenanceResourceQuota: 1);
        var source = new TokenKey("https://ap.example", "agent");
        var binding = new TokenKey("https://ps.example", "agent-person-binding https://ap.example aauth:agent@example");
        var caller = new UpstreamCallerRecord("https://ap.example", "aauth:agent@example", source, binding);
        var expiry = clock.GetUtcNow().AddMinutes(10);
        await store.RegisterAsync(source, expiry);
        await store.RegisterAsync(binding, DateTimeOffset.MaxValue.AddDays(-1));
        Assert.True(await store.RegisterGrantAsync([source, binding], new TokenGrant(
            new TokenKey("https://ps.example", "one"), "https://r1.example", expiry)
        {
            Provenance = new AAuthTokenProvenance(AAuthConstants.TokenTypes.PersonToken,
                "https://r1.example", "person-sub", "https://ps.example", caller),
        }));

        var minted = false;
        var result = await AuthTokenResponse.CreateTrackedAsync(_ =>
        {
            minted = true;
            return ValueTask.FromResult("not-a-token");
        }, expiry, store, [new TokenRegistration(source, expiry), new TokenRegistration(binding, DateTimeOffset.MaxValue.AddDays(-1))],
            "person_token", clock, provenance: new AAuthTokenProvenance(AAuthConstants.TokenTypes.PersonToken,
                "https://r2.example", "person-sub", "https://ps.example", caller));

        Assert.False(minted);
        Assert.Equal(StatusCodes.Status429TooManyRequests, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
    }

    private sealed class MutableClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}