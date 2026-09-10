using AAuth.Samples.Events;
using Microsoft.Data.Sqlite;

namespace AAuth.Events.Tests;

public class EventPersistenceTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "events-" + Guid.NewGuid().ToString("N") + ".db");
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private SqliteEventStore Store() => new(_path);
    private static EventEnvelope Envelope(string token = "token") => new(token, "eid", "https://resource.example",
        "aauth:agent@ap.example", Now.AddMinutes(5), [1, 2, 3]);

    [Fact]
    public async Task ConcurrentQuotaIsAtomicAndRetriesSurviveRestart()
    {
        Store().Create(new("eid", "aauth:agent@ap.example", "https://resource.example", Now.AddHours(1), 3));
        var results = await Task.WhenAll(Enumerable.Range(0, 30).Select(index => Task.Run(() => Store().Accept(Envelope("token-" + index), Now))));
        Assert.Equal(3, results.Count(result => result.StatusCode == 202));
        Assert.Equal(27, results.Count(result => result.StatusCode == 429));
        var pending = Store().Pending("aauth:agent@ap.example");
        Assert.Equal(3, pending.Count);
        Assert.Equal(new EventAcceptance(202, 0), Store().Accept(pending[0].Event, Now));
        Assert.False(Store().Acknowledge("aauth:other@ap.example", pending[0].Receipt));
        Assert.True(Store().Acknowledge("aauth:agent@ap.example", pending[0].Receipt));
        Assert.Equal(2, Store().Pending("aauth:agent@ap.example").Count);
    }

    [Fact]
    public void FailedOutboxWriteRollsBackQuota()
    {
        Store().Create(new("eid", "aauth:agent@ap.example", "https://resource.example", Now.AddHours(1), 1));
        using var connection = new SqliteConnection("Data Source=" + _path);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TRIGGER fail_outbox BEFORE INSERT ON event_outbox BEGIN SELECT RAISE(ABORT, 'failure'); END;";
        command.ExecuteNonQuery();
        Assert.Throws<SqliteException>(() => Store().Accept(Envelope(), Now));
        Assert.Empty(Store().Pending("aauth:agent@ap.example"));
        command.CommandText = "DROP TRIGGER fail_outbox";
        command.ExecuteNonQuery();
        Assert.Equal(new EventAcceptance(202, 0), Store().Accept(Envelope(), Now));
    }

    [Fact]
    public void UnlimitedAndBindingAndExpiry()
    {
        Store().Create(new("eid", "aauth:agent@ap.example", "https://resource.example", Now.AddHours(1), null));
        for (var index = 0; index < 8; index++) Assert.Equal(new EventAcceptance(202), Store().Accept(Envelope("token" + index), Now));
        Assert.Equal(403, Store().Accept(Envelope() with { Issuer = "https://other.example" }, Now).StatusCode);
        Assert.Equal(403, Store().Accept(Envelope() with { Agent = "aauth:other@ap.example" }, Now).StatusCode);
        Assert.Equal(404, Store().Accept(Envelope() with { Eid = "unknown" }, Now).StatusCode);
        Assert.Equal(404, Store().Accept(Envelope(), Now.AddHours(2)).StatusCode);
        Assert.Equal(400, Store().Accept(Envelope() with { ExpiresAt = Now }, Now).StatusCode);
    }

    [Fact]
    public async Task TicketRedemptionIsAtomicAndPreservesAccount()
    {
        Store().SetState("receive", "work", "state-1");
        Store().IssueTicket(new("ticket", "aauth:agent@ap.example", "receive", "work", "state-1", Now.AddMinutes(2)));
        ResourceSubscription Subscription(int index) => new("eid" + index, "https://ap.example", "aauth:agent@ap.example", "receive", null, "", Now.AddDays(1));
        Assert.Equal(403, Store().Register(Subscription(0) with { Agent = "aauth:other@ap.example" }, "ticket", Now).StatusCode);
        Assert.Equal(403, Store().Register(Subscription(0) with { Operation = "other" }, "ticket", Now).StatusCode);
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Task.Run(() => Store().Register(Subscription(index), "ticket", Now))));
        var success = Assert.Single(results, result => result.StatusCode == 200);
        Assert.Equal("work", success.Subscription!.Account);
        Assert.Equal("state-1", Store().Find("https://ap.example", success.Subscription.Eid, Now)!.State);
    }

    [Fact]
    public void StaleAndExpiredTicketsAndDuplicateRegistrationsFail()
    {
        Store().SetState("receive", "work", "new-state");
        Store().IssueTicket(new("stale", "aauth:agent@ap.example", "receive", "work", "old-state", Now.AddMinutes(2)));
        Store().IssueTicket(new("expired", "aauth:agent@ap.example", "receive", "work", "new-state", Now));
        var subscription = new ResourceSubscription("eid", "https://ap.example", "aauth:agent@ap.example", "receive", null, "", Now.AddDays(1));
        Assert.Equal(409, Store().Register(subscription, "stale", Now).StatusCode);
        Assert.Equal(404, Store().Register(subscription, "expired", Now).StatusCode);
        Assert.Equal(200, Store().Register(subscription, null, Now).StatusCode);
        Assert.Equal(409, Store().Register(subscription, null, Now).StatusCode);
    }

    [Fact]
    public void AgentContextAndLiteralIssuerEidDedupPersist()
    {
        var context = new AgentEventContext("eid", "https://resource.example", "aauth:agent@ap.example", "work reservation");
        Store().Remember(context);
        Assert.Equal(context, Store().FindContext("eid"));
        Assert.True(Store().RecordOnce(new(context, Envelope()), Now));
        Assert.False(Store().RecordOnce(new(context, Envelope("different-token")), Now));
        Assert.False(Store().RecordOnce(new(context, Envelope() with { ExpiresAt = Now }), Now));
        Assert.Single(Store().ReadEvents(context.Agent));
    }

    [Fact]
    public void ResourceFailureRollsBackTicketAndPreparedDeliverySurvivesRestart()
    {
        Store().SetState("receive", "work", "state");
        Store().IssueTicket(new("ticket", "aauth:agent@ap.example", "receive", "work", "state", Now.AddMinutes(5)));
        var subscription = new ResourceSubscription("eid", "https://ap.example", "aauth:agent@ap.example", "receive", null, "", Now.AddHours(1));
        using var connection = new SqliteConnection("Data Source=" + _path);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TRIGGER fail_registration BEFORE INSERT ON resource_subscriptions BEGIN SELECT RAISE(ABORT, 'failure'); END;";
        command.ExecuteNonQuery();
        Assert.Throws<SqliteException>(() => Store().Register(subscription, "ticket", Now));
        command.CommandText = "DROP TRIGGER fail_registration";
        command.ExecuteNonQuery();
        Assert.Equal(200, Store().Register(subscription, "ticket", Now).StatusCode);
        var first = Store().PrepareDelivery(subscription.Provider, subscription.Eid, () => Envelope());
        var retry = Store().PrepareDelivery(subscription.Provider, subscription.Eid, () => throw new InvalidOperationException("must not reissue"));
        Assert.Equal(first.Token, retry.Token);
        Assert.Equal(first.Body, retry.Body);
    }

    [Fact]
    public void RetryCannotReplacePersistedBodyOrReconsumeQuota()
    {
        Store().Create(new("eid", "aauth:agent@ap.example", "https://resource.example", Now.AddHours(1), 2));
        Assert.Equal(new EventAcceptance(202, 1), Store().Accept(Envelope(), Now));
        Assert.Equal(400, Store().Accept(Envelope() with { Body = [9] }, Now).StatusCode);
        Assert.Equal(new EventAcceptance(202, 1), Store().Accept(Envelope(), Now));
        Assert.Equal(new byte[] { 1, 2, 3 }, Assert.Single(Store().Pending("aauth:agent@ap.example")).Event.Body);
    }

    public void Dispose()
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" }) File.Delete(_path + suffix);
    }
}