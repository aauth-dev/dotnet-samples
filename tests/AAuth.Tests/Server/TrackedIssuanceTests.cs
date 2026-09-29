using AAuth.Server;
using Microsoft.AspNetCore.Http;

namespace AAuth.Tests.Server;

public class TrackedIssuanceTests
{
    [Fact]
    public async Task GrantRegistrationRejectsDependencyCycle()
    {
        var inventory = new InMemoryJtiStore();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(2);
        var root = new TokenKey("https://issuer.example", "root");
        var child = new TokenKey("https://issuer.example", "child");
        Assert.True(await inventory.RegisterAsync(root, expiry));
        Assert.True(await inventory.RegisterGrantAsync([root], new(child, "https://resource.example", expiry)));
        Assert.False(await inventory.RegisterGrantAsync([child], new(root, "https://resource.example", expiry)));
    }

    [Fact]
    public async Task RevokedAncestorBlocksEveryDescendantAndConcurrentExtension()
    {
        var inventory = new InMemoryJtiStore();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(2);
        var root = new TokenKey("https://issuer.example", "root");
        var child = new TokenKey("https://issuer.example", "child");
        var grandchild = new TokenKey("https://issuer.example", "grandchild");
        Assert.True(await inventory.RegisterAsync(root, expiry));
        Assert.True(await inventory.RegisterGrantAsync([root], new(child, "https://first.example", expiry)));
        Assert.True(await inventory.RegisterGrantAsync([child], new(grandchild, "https://second.example", expiry)));
        var extensions = Enumerable.Range(0, 40).Select(async index =>
        {
            var token = new TokenKey("https://issuer.example", "race-" + index);
            await Task.Yield();
            var accepted = await inventory.RegisterGrantAsync([grandchild], new(token, "https://last.example", expiry));
            return (token, accepted);
        }).ToArray();
        await inventory.RevokeAsync(root, expiry);
        foreach (var (token, accepted) in await Task.WhenAll(extensions))
            if (accepted) Assert.True(await inventory.IsRevokedAsync(token));
        Assert.True(await inventory.IsRevokedAsync(grandchild));
        Assert.False(await inventory.RegisterAsync(grandchild, expiry));
        Assert.False(await inventory.RegisterGrantAsync([grandchild], new(new("https://issuer.example", "late"), "https://last.example", expiry)));
        var result = await AuthTokenResponse.CreateTrackedAsync(
            _ => throw new InvalidOperationException("Revoked ancestry must be checked before mint."), expiry, inventory, [grandchild]);
        Assert.Equal(403, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
    }

    [Fact]
    public async Task KnownRevokedSourceIsRejectedBeforeMint()
    {
        var inventory = new InMemoryJtiStore();
        var upstream = new TokenKey("https://issuer.example", "upstream");
        var ceiling = DateTimeOffset.UtcNow.AddMinutes(2);
        Assert.True(await inventory.RegisterAsync(upstream, ceiling));
        await inventory.RevokeAsync(upstream, ceiling);
        var result = await AuthTokenResponse.CreateTrackedAsync(
            _ => throw new InvalidOperationException("Mint must not run for an already revoked upstream."),
            ceiling, inventory, [upstream]);
        Assert.Equal(403, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
    }
}