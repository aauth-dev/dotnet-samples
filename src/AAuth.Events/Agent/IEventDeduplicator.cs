using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.Agent;

/// <summary>
/// Atomically records an event idempotency key.
/// </summary>
/// <remarks>
/// Implementations are expected to retain a successful key for the period in
/// which a caller considers a replay. A durable implementation is required
/// when replay protection must survive process failure; the package's in-memory
/// implementation is convenience-only.
/// </remarks>
public interface IEventDeduplicator
{
    /// <summary>
    /// Attempts to record <paramref name="idempotencyKey"/>.
    /// </summary>
    /// <returns><see langword="true"/> only for the first recording.</returns>
    ValueTask<bool> TryRecordAsync(
        string idempotencyKey,
        CancellationToken cancellationToken = default);
}
