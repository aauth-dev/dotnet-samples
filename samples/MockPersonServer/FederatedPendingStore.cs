using System.Collections.Concurrent;

namespace MockPersonServer;

/// <summary>
/// Parks an in-flight four-party (federated) request while the PS drives the
/// Access Server interaction to completion in the background. Unlike
/// <see cref="PendingStore"/> (which tracks consent for the PS's own
/// three-party mint), this stores the relayed AS interaction the agent must
/// surface to its user, plus the terminal outcome (the AS-issued auth token or
/// a relayed error) once the PS's background <c>FederateAsync</c> resolves.
///
/// Demo-only: a process-wide dictionary with no expiry. A production PS would
/// persist these with a TTL and bind them to the calling agent.
/// </summary>
public sealed class FederatedPendingStore
{
    private readonly ConcurrentDictionary<string, FederatedPendingEntry> _entries = new();

    public FederatedPendingEntry Add()
    {
        var entry = new FederatedPendingEntry { Id = Guid.NewGuid().ToString("N") };
        _entries[entry.Id] = entry;
        return entry;
    }

    public FederatedPendingEntry? Get(string id) =>
        _entries.TryGetValue(id, out var entry) ? entry : null;

    public void Clear() => _entries.Clear();
}

public enum FederatedPendingStatus
{
    Pending,
    Allowed,
    Denied,
}

public sealed class FederatedPendingEntry
{
    public required string Id { get; init; }

    public FederatedPendingStatus Status { get; set; } = FederatedPendingStatus.Pending;

    /// <summary>The AS-issued auth token, set once federation succeeds.</summary>
    public string? AuthToken { get; set; }

    /// <summary>Relayed error code (e.g. <c>access_denied</c>) on failure.</summary>
    public string? Error { get; set; }

    /// <summary>HTTP status to relay to the agent for <see cref="Error"/>.</summary>
    public int ErrorStatus { get; set; }

    /// <summary>Optional <c>Location</c> to relay (e.g. a 402 payment URL).</summary>
    public string? ErrorLocation { get; set; }

    /// <summary>The AS user-facing interaction URL the agent must surface.</summary>
    public string? InteractionUrl { get; set; }

    /// <summary>The single-use interaction code paired with <see cref="InteractionUrl"/>.</summary>
    public string? InteractionCode { get; set; }

    /// <summary>
    /// Completed once the entry has produced its first agent-facing answer:
    /// either the AS interaction was captured (relay a 202), or federation
    /// reached a terminal state before any interaction (return directly).
    /// </summary>
    public TaskCompletionSource FirstAnswer { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
