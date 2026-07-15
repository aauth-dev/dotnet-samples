using AAuth.Crypto;
using AAuth.Events.AgentProvider;
using AAuth.Events.Tokens;
using Xunit;

namespace AAuth.Events.Tests.AgentProvider;

public sealed class AgentProviderContractTests
{
    [Fact]
    public async Task IssuerRetriesCollisionAndReturnsOnlyPersistedToken()
    {
        var store = new RecordingStore { CollisionCount = 1 };
        var ids = new Queue<string>(new[] { "collision", "fresh" });
        var now = new DateTimeOffset(2026, 7, 15, 7, 0, 0, TimeSpan.Zero);
        var key = AAuthKey.Generate();
        var issuer = new SubscribeTokenIssuer(store, new SubscribeTokenIssuerOptions
        {
            Issuer = "https://ap.example",
            Agent = "aauth:agent@example.com",
            Resource = "https://resource.example",
            KeyId = "ap-1",
            Key = key,
            ConfirmationKey = AAuthKey.Generate(),
            Lifetime = TimeSpan.FromMinutes(10),
            Clock = () => now,
            EidGenerator = () => ids.Dequeue(),
        });

        var artifact = await issuer.IssueAsync();

        Assert.Equal("fresh", artifact.Eid);
        Assert.Equal(2, store.Seen.Count);
        Assert.Equal("fresh", store.Subscription!.Eid);
    }

    [Fact]
    public void IncomingEventCopiesPayloadAndDigest()
    {
        var claims = new EventTokenClaims(
            "https://resource.example", "aauth:agent@example.com", "eid", "jti",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), "resource-1");
        var payload = new byte[] { 1, 2 };
        var digest = new byte[] { 3, 4 };
        var incoming = new IncomingEvent("header.payload.signature", claims, payload, "application/json", digest);

        payload[0] = 9;
        digest[0] = 9;

        Assert.Equal(new byte[] { 1, 2 }, incoming.RawPayloadBytes);
        Assert.Equal(new byte[] { 3, 4 }, incoming.ContentDigest);
        Assert.Equal(32, incoming.TokenHash.Length);
    }

    private sealed class RecordingStore : IAAuthAgentProviderEventStore
    {
        public int CollisionCount { get; set; }
        public List<string> Seen { get; } = new();
        public AgentProviderSubscription? Subscription { get; private set; }

        public Task<bool> TryCreateSubscriptionAsync(
            AgentProviderSubscription subscription,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Seen.Add(subscription.Eid);
            if (CollisionCount-- > 0) return Task.FromResult(false);
            Subscription = subscription;
            return Task.FromResult(true);
        }

        public Task<EventAcceptanceResult> AcceptEventAsync(
            IncomingEvent incomingEvent,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(EventAcceptanceResult.Accepted(incomingEvent));
    }
}
