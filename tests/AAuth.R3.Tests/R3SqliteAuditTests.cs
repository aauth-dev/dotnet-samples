using AAuth.R3;
using Microsoft.Data.Sqlite;
using R3AccessServer;

namespace AAuth.R3.Tests;

public class R3SqliteAuditTests
{
    [Fact]
    public async Task Commit_SurvivesRestartAndConcurrentIssuance()
    {
        var directory = Path.Combine(Directory.GetCurrentDirectory(), ".test-results", "r3-audit-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "audit.sqlite");
        try
        {
            var sink = new SqliteR3AuditSink(path);
            await Task.WhenAll(Enumerable.Range(0, 12).Select(index => Task.Run(() => sink.RecordTokenIssuanceAsync(Record(index.ToString())))));
            var recovered = new SqliteR3AuditSink(path).ReadRecords();
            Assert.Equal(12, recovered.Count);
            Assert.Equal(12, recovered.Select(record => record.TokenId).Distinct().Count());
            Assert.All(recovered, record => Assert.Equal("token-hash-" + record.TokenId, record.TokenS256));
            await Assert.ThrowsAsync<SqliteException>(() => sink.RecordTokenIssuanceAsync(Record("0")));
            Assert.Equal(12, new SqliteR3AuditSink(path).ReadRecords().Count);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task AuditInsertFailure_RollsBackTokenAssociationAndAllowsRecovery()
    {
        var directory = Path.Combine(Directory.GetCurrentDirectory(), ".test-results", "r3-audit-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "audit.sqlite");
        try
        {
            var sink = new SqliteR3AuditSink(path);
            using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "CREATE TRIGGER reject_audit BEFORE INSERT ON r3_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;";
                command.ExecuteNonQuery();
                await Assert.ThrowsAsync<SqliteException>(() => sink.RecordTokenIssuanceAsync(Record("retry")));
                command.CommandText = "SELECT COUNT(*) FROM r3_issuance";
                Assert.Equal(0L, command.ExecuteScalar());
                command.CommandText = "DROP TRIGGER reject_audit";
                command.ExecuteNonQuery();
            }
            Assert.Empty(new SqliteR3AuditSink(path).ReadRecords());
            await new SqliteR3AuditSink(path).RecordTokenIssuanceAsync(Record("retry"));
            Assert.Single(new SqliteR3AuditSink(path).ReadRecords());
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void MemoryDatabase_IsNotAcceptedAsDurable() =>
        Assert.Throws<ArgumentException>(() => new SqliteR3AuditSink(":memory:"));

    private static R3TokenIssuanceAuditRecord Record(string id) => new(
        "https://resource.test/r3/doc", "document-hash", "agent", "https://resource.test", "https://as.test",
        "https://ps.test", "person-1", "agent-jkt",
        DateTimeOffset.UtcNow, R3TokenIssuanceKind.Class) { TokenId = id, TokenS256 = "token-hash-" + id };
}