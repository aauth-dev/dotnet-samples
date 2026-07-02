namespace AAuth.R3;

/// <summary>Distinguishes class R3 issuance from per-call proposal issuance.</summary>
public enum R3TokenIssuanceKind
{
    Class,
    Proposal,
}

/// <summary>Audit metadata recorded by an AS when issuing an R3 auth token.</summary>
public sealed record R3TokenIssuanceAuditRecord(
    string R3Uri,
    string R3S256,
    string AgentId,
    string ResourceIssuer,
    string AccessServerIssuer,
    DateTimeOffset IssuedAt,
    R3TokenIssuanceKind IssuanceKind);

/// <summary>AS-side sink for durable R3 token-issuance audit records.</summary>
public interface IR3AuditSink
{
    /// <summary>Records token issuance metadata before the AS returns the auth token.</summary>
    Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default);
}

/// <summary>
/// No-op audit sink for tests and samples. Production AS deployments should configure
/// a durable <see cref="IR3AuditSink"/>; token issuance fails if that configured sink throws.
/// </summary>
public sealed class R3NoOpAuditSink : IR3AuditSink
{
    public static R3NoOpAuditSink Instance { get; } = new();

    private R3NoOpAuditSink()
    {
    }

    public Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return Task.CompletedTask;
    }
}

/// <summary>Simple in-memory R3 audit sink for tests and mock-server diagnostics.</summary>
public sealed class InMemoryR3AuditSink : IR3AuditSink
{
    private readonly object gate = new();
    private readonly List<R3TokenIssuanceAuditRecord> records = [];

    public IReadOnlyList<R3TokenIssuanceAuditRecord> Records
    {
        get
        {
            lock (gate)
            {
                return records.ToArray();
            }
        }
    }

    public Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            records.Add(record);
        }
        return Task.CompletedTask;
    }
}
