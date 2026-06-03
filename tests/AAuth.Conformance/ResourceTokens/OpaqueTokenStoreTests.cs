using System;
using System.Threading.Tasks;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Xunit;

namespace AAuth.Conformance.ResourceTokens;

/// <summary>
/// Conformance tests for resource-managed opaque tokens (§1.1, 2-party flow).
/// </summary>
public class OpaqueTokenStoreTests
{
    [Fact(DisplayName = "§1.1 — IOpaqueTokenStore: issue and validate round-trip")]
    public async Task IssueAndValidate_RoundTrip()
    {
        var store = new InMemoryOpaqueTokenStore();
        var info = new OpaqueTokenInfo
        {
            AgentJkt = "thumbprint123",
            Scope = "read write",
            Expiration = DateTimeOffset.UtcNow.AddMinutes(5),
        };
        var token = await store.IssueAsync(info);
        Assert.NotEmpty(token);

        var validated = await store.ValidateAsync(token);
        Assert.NotNull(validated);
        Assert.Equal("thumbprint123", validated!.AgentJkt);
        Assert.Equal("read write", validated.Scope);
    }

    [Fact(DisplayName = "§1.1 — IOpaqueTokenStore: expired token returns null")]
    public async Task ExpiredToken_ReturnsNull()
    {
        var store = new InMemoryOpaqueTokenStore();
        var info = new OpaqueTokenInfo
        {
            AgentJkt = "thumbprint123",
            Expiration = DateTimeOffset.UtcNow.AddSeconds(-1), // Already expired
        };
        var token = await store.IssueAsync(info);
        var validated = await store.ValidateAsync(token);
        Assert.Null(validated);
    }

    [Fact(DisplayName = "§1.1 — IOpaqueTokenStore: revoked token returns null")]
    public async Task RevokedToken_ReturnsNull()
    {
        var store = new InMemoryOpaqueTokenStore();
        var info = new OpaqueTokenInfo
        {
            AgentJkt = "thumbprint123",
            Expiration = DateTimeOffset.UtcNow.AddMinutes(5),
        };
        var token = await store.IssueAsync(info);
        await store.RevokeAsync(token);
        var validated = await store.ValidateAsync(token);
        Assert.Null(validated);
    }

    [Fact(DisplayName = "§1.1 — IOpaqueTokenStore: unknown token returns null")]
    public async Task UnknownToken_ReturnsNull()
    {
        var store = new InMemoryOpaqueTokenStore();
        var validated = await store.ValidateAsync("nonexistent");
        Assert.Null(validated);
    }
}
