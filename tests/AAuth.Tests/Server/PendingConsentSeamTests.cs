using AAuth.Crypto;
using AAuth.Person;
using AAuth.Server;
using Xunit;

namespace AAuth.Tests.Server;

/// <summary>The consent-dashboard seams: observing parked requests and deciding them out of band.</summary>
public class PendingConsentSeamTests
{
    [Fact]
    public void Observer_SeesEveryParkedEntryOnce()
    {
        var seen = new List<PersonPendingEntry>();
        var store = new ObservedPersonPendingStore(new InMemoryPersonPendingStore(), [new Observer(seen), new Observer(seen)]);

        var entry = store.Add("https://resource.example", "read", "aauth:agent@ap.example", AAuthKey.Generate(),
            DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.Equal([entry, entry], seen);
        Assert.Same(entry, store.Get(entry.Id));
        Assert.Same(entry, store.GetByCode(entry.Browser.Code));
    }

    [Fact]
    public async Task CompleteOutOfBand_AppliedDecisionConsumesTheCode()
    {
        var entry = new InMemoryPersonPendingStore().Add("https://resource.example", "read", "aauth:agent@ap.example",
            AAuthKey.Generate(), DateTimeOffset.UtcNow.AddMinutes(5));
        var generation = entry.Browser.Generation;

        Assert.True(await entry.Browser.CompleteOutOfBandAsync(entry.Lifecycle, _ => Task.FromResult(true)));

        Assert.True(entry.Browser.Consumed);
        Assert.NotEqual(generation, entry.Browser.Generation);
    }

    [Fact]
    public async Task CompleteOutOfBand_DecisionThatDoesNotApply_LeavesTheCodeOpen()
    {
        var entry = new InMemoryPersonPendingStore().Add("https://resource.example", "read", "aauth:agent@ap.example",
            AAuthKey.Generate(), DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.False(await entry.Browser.CompleteOutOfBandAsync(entry.Lifecycle, _ => Task.FromResult(false)));
        Assert.False(entry.Browser.Consumed);
    }

    [Fact]
    public async Task CompleteOutOfBand_WithdrawnRequest_IsNotDecided()
    {
        var entry = new InMemoryPersonPendingStore().Add("https://resource.example", "read", "aauth:agent@ap.example",
            AAuthKey.Generate(), DateTimeOffset.UtcNow.AddMinutes(5));
        entry.Lifecycle.Cancel();

        Assert.False(await entry.Browser.CompleteOutOfBandAsync(entry.Lifecycle,
            _ => throw new InvalidOperationException("A withdrawn request is never decided.")));
    }

    private sealed class Observer(List<PersonPendingEntry> seen) : IPersonPendingObserver
    {
        public void OnParked(PersonPendingEntry entry) => seen.Add(entry);
    }
}
