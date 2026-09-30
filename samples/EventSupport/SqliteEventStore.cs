using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AAuth.Events;
using Microsoft.Data.Sqlite;

namespace AAuth.Samples.Events;

public sealed class SqliteEventStore : IAgentProviderEventStore, IResourceEventStore, IAgentEventStore
{
    public const int InboxMaxBytes = 1024 * 1024;
    public static JsonSerializerOptions InboxJson { get; } = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;

    public SqliteEventStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path == ":memory:")
            throw new ArgumentException("Events require a persistent database file.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Pooling = false }.ToString();
        using var connection = Open();
        Execute(connection, null, """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS provider_subscriptions (
                eid TEXT PRIMARY KEY, agent TEXT NOT NULL, resource TEXT NOT NULL,
                expires INTEGER NOT NULL, maximum INTEGER CHECK(maximum > 0), uses INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS event_outbox (
                receipt TEXT PRIMARY KEY, eid TEXT NOT NULL, body_hash TEXT NOT NULL, agent TEXT NOT NULL,
                envelope TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(eid) REFERENCES provider_subscriptions(eid));
            CREATE INDEX IF NOT EXISTS pending_agent_events ON event_outbox(agent,acknowledged);
            CREATE TABLE IF NOT EXISTS resource_states (
                operation TEXT NOT NULL, account TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(operation,account));
            CREATE TABLE IF NOT EXISTS subscription_tickets (
                ticket TEXT PRIMARY KEY, record TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS resource_subscriptions (
                provider TEXT NOT NULL, eid TEXT NOT NULL, record TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(provider,eid));
            CREATE TABLE IF NOT EXISTS agent_contexts (eid TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resource_deliveries (
                provider TEXT NOT NULL, eid TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(provider,eid));
            CREATE TABLE IF NOT EXISTS delivery_receipts (
                provider TEXT NOT NULL, eid TEXT NOT NULL, agent TEXT NOT NULL, account TEXT NOT NULL,
                response TEXT NOT NULL, PRIMARY KEY(provider,eid));
            CREATE TABLE IF NOT EXISTS received_events (
                issuer TEXT NOT NULL, jti TEXT NOT NULL, agent TEXT NOT NULL, record TEXT NOT NULL,
                PRIMARY KEY(issuer,jti));
            """);
    }

    public void Create(ProviderSubscription subscription)
    {
        if (subscription.MaxUses <= 0) throw new ArgumentOutOfRangeException(nameof(subscription));
        using var connection = Open();
        Execute(connection, null, "INSERT INTO provider_subscriptions(eid,agent,resource,expires,maximum) VALUES($eid,$agent,$resource,$expires,$maximum)",
            ("$eid", subscription.Eid), ("$agent", subscription.Agent), ("$resource", subscription.Resource),
            ("$expires", subscription.ExpiresAt.ToUnixTimeSeconds()), ("$maximum", subscription.MaxUses));
    }

    public EventAcceptance Accept(EventEnvelope envelope, DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        using var lookup = Command(connection, transaction,
            "SELECT agent,resource,expires,maximum,uses FROM provider_subscriptions WHERE eid=$eid", ("$eid", envelope.Eid));
        string agent;
        string resource;
        long expires;
        long? maximum;
        long uses;
        using (var reader = lookup.ExecuteReader())
        {
            if (!reader.Read()) return new(EventAcceptanceOutcome.Unknown);
            agent = reader.GetString(0); resource = reader.GetString(1); expires = reader.GetInt64(2);
            maximum = reader.IsDBNull(3) ? null : reader.GetInt64(3); uses = reader.GetInt64(4);
        }
        if (expires <= now.ToUnixTimeSeconds()) return new(EventAcceptanceOutcome.Expired);
        if (resource != envelope.Issuer || agent != envelope.Agent) return new(EventAcceptanceOutcome.Forbidden);
        if (envelope.ExpiresAt <= now) return new(EventAcceptanceOutcome.Expired);
        // (iss, jti) identifies one event (Events L363); a re-signed copy is the same delivery.
        var receipt = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(envelope.Issuer + "\n" + envelope.Jti)));
        if (JsonSerializer.SerializeToUtf8Bytes(new PendingEvent(receipt, envelope), InboxJson).Length + 2 > InboxMaxBytes)
            throw new InvalidOperationException("Event envelope exceeds the durable inbox size limit.");
        var bodyHash = Convert.ToHexString(SHA256.HashData(envelope.Body));
        var prior = Scalar(connection, transaction, "SELECT body_hash FROM event_outbox WHERE receipt=$receipt", ("$receipt", receipt));
        if (prior is string priorHash)
            return priorHash == bodyHash ? new(EventAcceptanceOutcome.Duplicate, maximum - uses) : new(EventAcceptanceOutcome.Forbidden);
        if (maximum is not null && uses >= maximum) return new(EventAcceptanceOutcome.Exhausted);
        Execute(connection, transaction, "UPDATE provider_subscriptions SET uses=uses+1 WHERE eid=$eid", ("$eid", envelope.Eid));
        Execute(connection, transaction,
            "INSERT INTO event_outbox(receipt,eid,body_hash,agent,envelope) VALUES($receipt,$eid,$hash,$agent,$envelope)",
            ("$receipt", receipt), ("$eid", envelope.Eid), ("$hash", bodyHash), ("$agent", agent),
            ("$envelope", JsonSerializer.Serialize(envelope)));
        transaction.Commit();
        return new(EventAcceptanceOutcome.Accepted, maximum - uses - 1);
    }

    public IReadOnlyList<PendingEvent> Pending(string agent, int limit = 100, string? after = null)
    {
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        using var connection = Open();
        using var command = Command(connection, null,
            """
            SELECT receipt,envelope FROM event_outbox WHERE agent=$agent AND acknowledged=0
            AND rowid > CASE WHEN $after IS NULL THEN 0 ELSE
                (SELECT rowid FROM event_outbox WHERE receipt=$after AND agent=$agent) END
            ORDER BY rowid LIMIT $limit
            """, ("$agent", agent), ("$after", after), ("$limit", limit));
        using var reader = command.ExecuteReader();
        var result = new List<PendingEvent>();
        var bytes = 2;
        while (reader.Read())
        {
            var item = new PendingEvent(reader.GetString(0), JsonSerializer.Deserialize<EventEnvelope>(reader.GetString(1))!);
            var size = JsonSerializer.SerializeToUtf8Bytes(item, InboxJson).Length + (result.Count == 0 ? 0 : 1);
            if (bytes + size > InboxMaxBytes) break;
            result.Add(item);
            bytes += size;
        }
        return result;
    }

    public bool Acknowledge(string agent, string receipt)
    {
        using var connection = Open();
        return Execute(connection, null, "UPDATE event_outbox SET acknowledged=1 WHERE receipt=$receipt AND agent=$agent",
            ("$receipt", receipt), ("$agent", agent)) == 1;
    }

    public void SetState(string operation, string? account, string state)
    {
        using var connection = Open();
        Execute(connection, null, "INSERT INTO resource_states(operation,account,state) VALUES($op,$account,$state) ON CONFLICT(operation,account) DO UPDATE SET state=$state",
            ("$op", operation), ("$account", account ?? ""), ("$state", state));
    }

    public string EnsureState(string operation, string? account, string initialState)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        Execute(connection, transaction, "INSERT OR IGNORE INTO resource_states(operation,account,state) VALUES($op,$account,$state)",
            ("$op", operation), ("$account", account ?? ""), ("$state", initialState));
        var state = (string)Scalar(connection, transaction, "SELECT state FROM resource_states WHERE operation=$op AND account=$account",
            ("$op", operation), ("$account", account ?? ""))!;
        transaction.Commit();
        return state;
    }

    public async Task<EventEnvelope> PrepareDeliveryAsync(string provider, string eid, Func<Task<EventEnvelope>> create)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = Scalar(connection, transaction, "SELECT envelope FROM resource_deliveries WHERE provider=$provider AND eid=$eid",
            ("$provider", provider), ("$eid", eid)) as string;
        if (existing is not null) return JsonSerializer.Deserialize<EventEnvelope>(existing)!;
        var envelope = await create();
        Execute(connection, transaction, "INSERT INTO resource_deliveries(provider,eid,envelope) VALUES($provider,$eid,$envelope)",
            ("$provider", provider), ("$eid", eid), ("$envelope", JsonSerializer.Serialize(envelope)));
        transaction.Commit();
        return envelope;
    }

    public void IssueTicket(SubscriptionTicket ticket)
    {
        using var connection = Open();
        Execute(connection, null, "INSERT INTO subscription_tickets(ticket,record) VALUES($ticket,$record)",
            ("$ticket", ticket.Ticket), ("$record", JsonSerializer.Serialize(ticket)));
    }

    public RegistrationResult Register(ResourceSubscription subscription, string? ticket, DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        var existing = Scalar(connection, transaction,
            "SELECT 1 FROM resource_subscriptions WHERE provider=$provider AND eid=$eid", ("$provider", subscription.Provider), ("$eid", subscription.Eid));
        if (existing is not null) return new(409);
        if (ticket is not null)
        {
            var json = Scalar(connection, transaction,
                "SELECT record FROM subscription_tickets WHERE ticket=$ticket AND consumed=0", ("$ticket", ticket)) as string;
            if (json is null) return new(404);
            var authorization = JsonSerializer.Deserialize<SubscriptionTicket>(json)!;
            if (authorization.ExpiresAt <= now) return new(404);
            if (authorization.KeyThumbprint != subscription.KeyThumbprint || authorization.Operation != subscription.Operation) return new(403);
            var state = Scalar(connection, transaction, "SELECT state FROM resource_states WHERE operation=$op AND account=$account",
                ("$op", authorization.Operation), ("$account", authorization.Account ?? "")) as string;
            if (state != authorization.State) return new(409);
            subscription = subscription with { Account = authorization.Account, State = authorization.State };
            Execute(connection, transaction, "UPDATE subscription_tickets SET consumed=1 WHERE ticket=$ticket", ("$ticket", ticket));
        }
        if (subscription.ExpiresAt <= now) return new(400);
        Execute(connection, transaction,
            "INSERT INTO resource_subscriptions(provider,eid,record) VALUES($provider,$eid,$record)",
            ("$provider", subscription.Provider), ("$eid", subscription.Eid), ("$record", JsonSerializer.Serialize(subscription)));
        transaction.Commit();
        return new(200, subscription);
    }

    public ResourceSubscription? Find(string provider, string eid, DateTimeOffset now)
    {
        using var connection = Open();
        var json = Scalar(connection, null,
            "SELECT record FROM resource_subscriptions WHERE provider=$provider AND eid=$eid AND complete=0", ("$provider", provider), ("$eid", eid)) as string;
        if (json is null) return null;
        var subscription = JsonSerializer.Deserialize<ResourceSubscription>(json)!;
        return subscription.ExpiresAt > now ? subscription : null;
    }

    public ResourceSubscription? FindNotification(string provider, string eid)
    {
        using var connection = Open();
        var json = Scalar(connection, null, "SELECT record FROM resource_subscriptions WHERE provider=$provider AND eid=$eid",
            ("$provider", provider), ("$eid", eid)) as string;
        return json is null ? null : JsonSerializer.Deserialize<ResourceSubscription>(json);
    }

    public string? DeliveryReceipt(ResourceSubscription subscription)
    {
        using var connection = Open();
        return Scalar(connection, null,
            "SELECT response FROM delivery_receipts WHERE provider=$provider AND eid=$eid AND agent=$agent AND account=$account",
            ("$provider", subscription.Provider), ("$eid", subscription.Eid), ("$agent", subscription.Agent),
            ("$account", subscription.Account ?? "")) as string;
    }

    public string RecordDelivery(ResourceSubscription subscription, string response, bool complete)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        Execute(connection, transaction,
            "INSERT OR IGNORE INTO delivery_receipts(provider,eid,agent,account,response) VALUES($provider,$eid,$agent,$account,$response)",
            ("$provider", subscription.Provider), ("$eid", subscription.Eid), ("$agent", subscription.Agent),
            ("$account", subscription.Account ?? ""), ("$response", response));
        if (complete) Execute(connection, transaction, "UPDATE resource_subscriptions SET complete=1 WHERE provider=$provider AND eid=$eid",
            ("$provider", subscription.Provider), ("$eid", subscription.Eid));
        var receipt = (string)Scalar(connection, transaction, "SELECT response FROM delivery_receipts WHERE provider=$provider AND eid=$eid",
            ("$provider", subscription.Provider), ("$eid", subscription.Eid))!;
        transaction.Commit();
        return receipt;
    }

    public void Complete(string provider, string eid)
    {
        using var connection = Open();
        Execute(connection, null, "UPDATE resource_subscriptions SET complete=1 WHERE provider=$provider AND eid=$eid",
            ("$provider", provider), ("$eid", eid));
    }

    public void Remember(AgentEventContext context)
    {
        using var connection = Open();
        Execute(connection, null, "INSERT INTO agent_contexts(eid,record) VALUES($eid,$record)",
            ("$eid", context.Eid), ("$record", JsonSerializer.Serialize(context)));
    }

    public AgentEventContext? FindContext(string eid)
    {
        using var connection = Open();
        var json = Scalar(connection, null, "SELECT record FROM agent_contexts WHERE eid=$eid", ("$eid", eid)) as string;
        return json is null ? null : JsonSerializer.Deserialize<AgentEventContext>(json);
    }

    public bool RecordOnce(ProcessedEvent received, DateTimeOffset now)
    {
        if (received.Event.ExpiresAt <= now || received.Context.Agent != received.Event.Agent
            || received.Context.Resource != received.Event.Issuer || received.Context.Eid != received.Event.Eid) return false;
        using var connection = Open();
        return Execute(connection, null, "INSERT OR IGNORE INTO received_events(issuer,jti,agent,record) VALUES($issuer,$jti,$agent,$record)",
            ("$issuer", received.Event.Issuer), ("$jti", received.Event.Jti), ("$agent", received.Event.Agent),
            ("$record", JsonSerializer.Serialize(received))) == 1;
    }

    public IReadOnlyList<ProcessedEvent> ReadEvents(string agent)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT record FROM received_events WHERE agent=$agent ORDER BY rowid", ("$agent", agent));
        using var reader = command.ExecuteReader();
        var events = new List<ProcessedEvent>();
        while (reader.Read()) events.Add(JsonSerializer.Deserialize<ProcessedEvent>(reader.GetString(0))!);
        return events;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            Execute(connection, null, "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;");
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }

    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction,
        string sql, params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        return command;
    }

    private static int Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, transaction, sql, parameters);
        return command.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, transaction, sql, parameters);
        return command.ExecuteScalar();
    }
}