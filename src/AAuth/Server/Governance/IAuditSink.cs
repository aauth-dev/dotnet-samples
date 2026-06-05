using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// PS-side sink for audit records (§Audit Endpoint). The PS records the entry in
/// the mission log and MAY use it to detect anomalous behavior, alert the user,
/// or revoke the mission. The SDK supplies the contract; the PS implements
/// storage/alerting policy.
/// </summary>
public interface IAuditSink
{
    /// <summary>Record an audit entry the agent reported within a mission context.</summary>
    Task RecordAsync(AuditRecord record, CancellationToken ct = default);
}
