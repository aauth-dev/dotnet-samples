using System.Text.Json;
using AAuth.R3;
using Microsoft.Data.Sqlite;

namespace R3AccessServer;

public sealed class SqliteR3AuditSink : IR3AuditSink
{
    private readonly string _connectionString;

    public SqliteR3AuditSink(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path == ":memory:") throw new ArgumentException("R3 audit requires a persistent database file.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Pooling = false }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS r3_issuance (
                issuer TEXT NOT NULL, token_id TEXT NOT NULL, token_s256 TEXT NOT NULL,
                PRIMARY KEY (issuer, token_id), UNIQUE (token_s256));
            CREATE TABLE IF NOT EXISTS r3_audit (
                issuer TEXT NOT NULL, token_id TEXT NOT NULL, record TEXT NOT NULL,
                PRIMARY KEY (issuer, token_id),
                FOREIGN KEY (issuer, token_id) REFERENCES r3_issuance(issuer, token_id));
            """;
        command.ExecuteNonQuery();
    }

    public Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(record.TokenId);
        ArgumentException.ThrowIfNullOrWhiteSpace(record.TokenS256);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO r3_issuance (issuer, token_id, token_s256) VALUES ($issuer, $id, $hash)";
        command.Parameters.AddWithValue("$issuer", record.AccessServerIssuer);
        command.Parameters.AddWithValue("$id", record.TokenId);
        command.Parameters.AddWithValue("$hash", record.TokenS256);
        command.ExecuteNonQuery();
        command.CommandText = "INSERT INTO r3_audit (issuer, token_id, record) VALUES ($issuer, $id, $record)";
        command.Parameters.AddWithValue("$record", JsonSerializer.Serialize(record));
        command.ExecuteNonQuery();
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
        return Task.CompletedTask;
    }

    public IReadOnlyList<R3TokenIssuanceAuditRecord> ReadRecords()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT record FROM r3_audit ORDER BY rowid";
        using var reader = command.ExecuteReader();
        var records = new List<R3TokenIssuanceAuditRecord>();
        while (reader.Read()) records.Add(JsonSerializer.Deserialize<R3TokenIssuanceAuditRecord>(reader.GetString(0))!);
        return records;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;";
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }
}