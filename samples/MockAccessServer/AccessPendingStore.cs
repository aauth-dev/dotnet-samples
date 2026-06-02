using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace MockAccessServer;

/// <summary>
/// In-memory store of in-flight federated decisions awaiting an interactive
/// Keycloak login/consent round-trip. The AS parks the mint inputs here when a
/// policy returns <c>NeedsInteraction</c>, redirects the user through Keycloak,
/// and resumes (mint or deny) when the PS polls the pending URL.
///
/// Demo-only: a single process-wide dictionary with no expiry. A production AS
/// would persist these with a TTL and bind them to the calling PS.
/// </summary>
public sealed class AccessPendingStore
{
    private readonly ConcurrentDictionary<string, AccessPendingEntry> _entries = new();

    public AccessPendingEntry Add(
        string resourceUrl, string scope, string agentId,
        AAuthKey agentConfirmationKey, JsonObject? claims)
    {
        var entry = new AccessPendingEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            ResourceUrl = resourceUrl,
            Scope = scope,
            AgentId = agentId,
            AgentConfirmationKey = agentConfirmationKey,
            Claims = claims,
            Status = AccessPendingStatus.Pending,
        };
        _entries[entry.Id] = entry;
        return entry;
    }

    public AccessPendingEntry? Get(string id) =>
        _entries.TryGetValue(id, out var entry) ? entry : null;

    public void MarkAllowed(string id)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Status = AccessPendingStatus.Allowed;
        }
    }

    public void MarkDenied(string id, string reason)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Status = AccessPendingStatus.Denied;
            entry.DenyReason = reason;
        }
    }

    public void Clear() => _entries.Clear();
}

public enum AccessPendingStatus
{
    Pending,
    Allowed,
    Denied,
}

public sealed class AccessPendingEntry
{
    public required string Id { get; init; }
    public required string ResourceUrl { get; init; }
    public required string Scope { get; init; }
    public required string AgentId { get; init; }
    public required AAuthKey AgentConfirmationKey { get; init; }
    public JsonObject? Claims { get; init; }
    public AccessPendingStatus Status { get; set; }
    public string? DenyReason { get; set; }
}
