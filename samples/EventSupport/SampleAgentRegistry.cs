using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.Data.Sqlite;

namespace AAuth.Samples.Events;

public sealed record SampleAgentRecord(string AgentId, IAAuthKey PublicKey, string KeyId,
    DateTimeOffset RegisteredAt, string? PersonServer);

public sealed class SampleAgentRegistry
{
    private readonly string _connectionString;

    public SampleAgentRegistry(string path)
    {
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Pooling = false }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS enrolled_agents (
                agent TEXT PRIMARY KEY, thumbprint TEXT NOT NULL UNIQUE, jwk TEXT NOT NULL,
                kid TEXT NOT NULL, registered TEXT NOT NULL, person_server TEXT);
            """;
        command.ExecuteNonQuery();
    }

    public SampleAgentRecord? Enrol(string issuer, string? requestedId, IAAuthKey publicKey, string? personServer)
    {
        var thumbprint = publicKey.ComputeJwkThumbprint();
        var assignedId = "aauth:agent-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(thumbprint))).ToLowerInvariant()
            + "@" + new Uri(issuer).IdnHost;
        if (requestedId is not null && requestedId != assignedId) return null;
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO enrolled_agents(agent,thumbprint,jwk,kid,registered,person_server)
            VALUES($agent,$thumbprint,$jwk,$kid,$registered,$ps)
            """;
        command.Parameters.AddWithValue("$agent", assignedId);
        command.Parameters.AddWithValue("$thumbprint", thumbprint);
        command.Parameters.AddWithValue("$jwk", publicKey.ToPublicJwk().ToJsonString());
        command.Parameters.AddWithValue("$kid", Guid.NewGuid().ToString("N"));
        command.Parameters.AddWithValue("$registered", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$ps", (object?)personServer ?? DBNull.Value);
        command.ExecuteNonQuery();
        command.CommandText = "SELECT agent,jwk,kid,registered,person_server FROM enrolled_agents WHERE agent=$agent AND thumbprint=$thumbprint";
        SampleAgentRecord? record;
        using (var reader = command.ExecuteReader()) record = reader.Read() ? Read(reader) : null;
        if (record is null || record.PersonServer != personServer) return null;
        transaction.Commit();
        return record;
    }

    public SampleAgentRecord? Find(string agent) => FindBy("agent", agent);
    public SampleAgentRecord? FindByKey(string thumbprint) => FindBy("thumbprint", thumbprint);

    private SampleAgentRecord? FindBy(string column, string value)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT agent,jwk,kid,registered,person_server FROM enrolled_agents WHERE {column}=$value";
        command.Parameters.AddWithValue("$value", value);
        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    public IReadOnlyList<SampleAgentRecord> List()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT agent,jwk,kid,registered,person_server FROM enrolled_agents ORDER BY agent";
        using var reader = command.ExecuteReader();
        var records = new List<SampleAgentRecord>();
        while (reader.Read()) records.Add(Read(reader));
        return records;
    }

    private static SampleAgentRecord Read(SqliteDataReader reader) => new(reader.GetString(0),
        KeyFactory.FromPublicJwk(JsonNode.Parse(reader.GetString(1))!.AsObject()), reader.GetString(2),
        DateTimeOffset.Parse(reader.GetString(3)), reader.IsDBNull(4) ? null : reader.GetString(4));

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA synchronous=FULL; PRAGMA busy_timeout=30000;";
            command.ExecuteNonQuery();
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }
}