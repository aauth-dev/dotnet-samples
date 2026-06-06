using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IAuditSink"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own sink. It appends the
/// reported action to the mission log (§Audit Endpoint) so the trail is
/// preserved. A PS that needs anomaly detection or alerting should override it.
/// </summary>
public sealed class DefaultAuditSink : IAuditSink
{
    private readonly IMissionLog _log;

    /// <summary>Create the default sink over the registered mission log.</summary>
    public DefaultAuditSink(IMissionLog log)
        => _log = log ?? throw new ArgumentNullException(nameof(log));

    /// <inheritdoc />
    public Task RecordAsync(AuditRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return _log.AppendAsync(
            new MissionLogEntry(record.Mission.S256, MissionLogEntryKind.Audit, DateTimeOffset.UtcNow)
            {
                Action = record.Action,
                Detail = record.Description,
            },
            ct);
    }
}
