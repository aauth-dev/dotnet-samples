using AAuth.Agent;
using AAuth.Server.Governance;

namespace AAuth.Tests.Server.Governance;

public class InMemoryMissionStoreTests
{
    [Fact]
    public async Task TerminateAsync_StoresReasonAndPreservesFirstReason()
    {
        var store = new InMemoryMissionStore();
        await store.SaveAsync(new StoredMission("s256", "https://ps.example", "aauth:a@example", ReadOnlyMemory<byte>.Empty));

        await store.TerminateAsync("https://ps.example", "s256", AAuthConstants.MissionTerminationReasons.Completed);
        await store.TerminateAsync("https://ps.example", "s256", AAuthConstants.MissionTerminationReasons.Administrative);

        var stored = await store.GetAsync("https://ps.example", "s256");
        Assert.Equal(MissionState.Terminated, stored!.State);
        Assert.Equal(AAuthConstants.MissionTerminationReasons.Completed, stored.TerminationReason);
        await Assert.ThrowsAsync<ArgumentException>(() => store.TerminateAsync("https://ps.example", "s256", " "));
    }

    [Fact]
    public async Task GetAsync_UsesPersonServerAndS256Pair()
    {
        var store = new InMemoryMissionStore();
        await store.SaveAsync(new StoredMission("same", "https://ps-a.example", "aauth:a@example", new byte[] { 1 }));
        await store.SaveAsync(new StoredMission("same", "https://ps-b.example", "aauth:b@example", new byte[] { 2 }));

        Assert.Equal("aauth:a@example", (await store.GetAsync("https://ps-a.example", "same"))!.Agent);
        Assert.Equal("aauth:b@example", (await store.GetAsync("https://ps-b.example", "same"))!.Agent);
        Assert.Null(await store.GetAsync("https://ps-c.example", "same"));
    }

    [Fact]
    public async Task SaveAsync_DoesNotReviveTerminatedMissionOrExtendExpiry()
    {
        var store = new InMemoryMissionStore();
        var early = DateTimeOffset.UtcNow.AddMinutes(5);
        await store.SaveAsync(new StoredMission("s256", "https://ps.example", "aauth:a@example", ReadOnlyMemory<byte>.Empty)
        {
            ExpiresAt = early,
        });
        await store.TerminateAsync("https://ps.example", "s256", AAuthConstants.MissionTerminationReasons.Revoked);

        await store.SaveAsync(new StoredMission("s256", "https://ps.example", "aauth:a@example", ReadOnlyMemory<byte>.Empty)
        {
            ExpiresAt = early.AddHours(1),
        });

        var stored = await store.GetAsync("https://ps.example", "s256");
        Assert.Equal(MissionState.Terminated, stored!.State);
        Assert.Equal(AAuthConstants.MissionTerminationReasons.Revoked, stored.TerminationReason);
        Assert.Equal(early, stored.ExpiresAt);
    }
}
