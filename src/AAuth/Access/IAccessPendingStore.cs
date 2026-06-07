using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Access;

/// <summary>
/// Stores in-flight federated access decisions awaiting either an interactive
/// user login/consent round-trip (§Trust Establishment) or a §Claims Required
/// push. The <c>MapAAuthAccessServer</c> host parks the mint inputs here when a
/// policy defers, and resumes (mint or deny) when the Person Server polls the
/// pending URL.
/// </summary>
public interface IAccessPendingStore
{
    /// <summary>Park a new pending decision and return the created entry.</summary>
    AccessPendingEntry Add(
        string resourceUrl,
        string scope,
        string agentId,
        IAAuthKey agentConfirmationKey,
        JsonObject? claims,
        IReadOnlyList<string>? requiredClaims = null);

    /// <summary>Look up a pending entry by id, or <see langword="null"/>.</summary>
    AccessPendingEntry? Get(string id);

    /// <summary>Mark the entry allowed (the poll will mint the auth token).</summary>
    void MarkAllowed(string id);

    /// <summary>Mark the entry denied with a reason.</summary>
    void MarkDenied(string id, string reason);
}

/// <summary>The lifecycle state of an <see cref="AccessPendingEntry"/>.</summary>
public enum AccessPendingStatus
{
    /// <summary>Awaiting the interaction/claims round-trip.</summary>
    Pending,

    /// <summary>Approved — the next poll mints the auth token.</summary>
    Allowed,

    /// <summary>Denied — the next poll returns <c>403 denied</c>.</summary>
    Denied,
}

/// <summary>A parked federated access decision.</summary>
public sealed class AccessPendingEntry
{
    /// <summary>Opaque pending id (path segment of the <c>Location</c> URL).</summary>
    public required string Id { get; init; }

    /// <summary>The resource URL the auth token will be audienced to.</summary>
    public required string ResourceUrl { get; init; }

    /// <summary>The requested scope.</summary>
    public required string Scope { get; init; }

    /// <summary>The verified agent identifier.</summary>
    public required string AgentId { get; init; }

    /// <summary>The agent's confirmation key (<c>cnf.jwk</c> binding).</summary>
    public required IAAuthKey AgentConfirmationKey { get; init; }

    /// <summary>
    /// The originating Person Server's <c>jwks_uri</c> host authority, captured
    /// when the decision was parked. The pending poll/push endpoints re-pin the
    /// caller to this host so a different (even trusted) Person Server cannot
    /// poll or push into another PS's entry.
    /// </summary>
    public string? OriginPersonServerHost { get; set; }

    /// <summary>Identity claims known when the decision was parked.</summary>
    public JsonObject? Claims { get; init; }

    /// <summary>
    /// Claim names the PS must push (§Claims Required), if any. Settable so an
    /// interactive policy that discovers a claim requirement mid-flight (e.g.
    /// Keycloak UMA <c>need_info</c>) can transition the entry into claims
    /// gathering on the same <c>Location</c>.
    /// </summary>
    public IReadOnlyList<string>? RequiredClaims { get; set; }

    /// <summary>The directed <c>sub</c> the PS supplied on the claims push.</summary>
    public string? SuppliedSubject { get; set; }

    /// <summary>The identity claims the PS pushed (§Claims Required).</summary>
    public JsonObject? SuppliedClaims { get; set; }

    /// <summary>The entry's lifecycle state.</summary>
    public AccessPendingStatus Status { get; set; }

    /// <summary>The denial reason when <see cref="Status"/> is Denied.</summary>
    public string? DenyReason { get; set; }

    /// <summary>When the entry was parked. Drives in-memory TTL eviction.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Process-wide in-memory <see cref="IAccessPendingStore"/>. Suitable for a
/// single-instance demo/sample; a production AS would persist entries with a
/// TTL and bind them to the calling Person Server.
/// <para>
/// Entries are evicted once they exceed <see cref="Ttl"/> (lazily, on each
/// <see cref="Add"/>/<see cref="Get"/>) so the dictionary does not grow without
/// bound. The TTL is generous enough to outlive the interactive round-trip and
/// any poll retries, so a successfully-minted entry is not yanked out from
/// under a re-polling Person Server.
/// </para>
/// </summary>
public sealed class InMemoryAccessPendingStore : IAccessPendingStore
{
    /// <summary>How long a parked entry is retained before it is evicted.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, AccessPendingEntry> _entries = new();

    /// <inheritdoc />
    public AccessPendingEntry Add(
        string resourceUrl,
        string scope,
        string agentId,
        IAAuthKey agentConfirmationKey,
        JsonObject? claims,
        IReadOnlyList<string>? requiredClaims = null)
    {
        Sweep();
        var entry = new AccessPendingEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            ResourceUrl = resourceUrl,
            Scope = scope,
            AgentId = agentId,
            AgentConfirmationKey = agentConfirmationKey,
            Claims = claims,
            RequiredClaims = requiredClaims,
            Status = AccessPendingStatus.Pending,
        };
        _entries[entry.Id] = entry;
        return entry;
    }

    /// <inheritdoc />
    public AccessPendingEntry? Get(string id)
    {
        Sweep();
        return _entries.TryGetValue(id, out var entry) ? entry : null;
    }

    /// <inheritdoc />
    public void MarkAllowed(string id)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Status = AccessPendingStatus.Allowed;
        }
    }

    /// <inheritdoc />
    public void MarkDenied(string id, string reason)
    {
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Status = AccessPendingStatus.Denied;
            entry.DenyReason = reason;
        }
    }

    /// <summary>Remove all entries (test helper).</summary>
    public void Clear() => _entries.Clear();

    /// <summary>Evict entries older than <see cref="Ttl"/>.</summary>
    private void Sweep()
    {
        var cutoff = DateTimeOffset.UtcNow - Ttl;
        foreach (var kv in _entries)
        {
            if (kv.Value.CreatedAt < cutoff)
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }
    }
}
