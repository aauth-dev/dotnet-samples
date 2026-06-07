using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Governance;

/// <summary>The kind of action recorded in a mission log entry (§Mission Log).</summary>
public enum MissionLogEntryKind
{
    /// <summary>A token request (with justification) the agent made under the mission.</summary>
    Token,

    /// <summary>A permission request and its decision.</summary>
    Permission,

    /// <summary>An audit record the agent reported.</summary>
    Audit,

    /// <summary>An interaction relayed through the PS.</summary>
    Interaction,

    /// <summary>A clarification chat exchange during review.</summary>
    Clarification,
}

/// <summary>
/// A single entry in the mission log (§Mission Log) — the ordered record of an
/// agent's actions and the governance decisions made within a mission context.
/// </summary>
/// <param name="S256">The mission this entry belongs to.</param>
/// <param name="Kind">The kind of action.</param>
/// <param name="Timestamp">When the entry was recorded.</param>
public sealed record MissionLogEntry(string S256, MissionLogEntryKind Kind, DateTimeOffset Timestamp)
{
    /// <summary>The resource involved (for token entries) — used for prior-consent lookups.</summary>
    public string? Resource { get; init; }

    /// <summary>The scope involved (for token entries) — used for prior-consent lookups.</summary>
    public string? Scope { get; init; }

    /// <summary>The action name (for permission / audit entries).</summary>
    public string? Action { get; init; }

    /// <summary>Whether the governance decision granted the request (for token / permission entries).</summary>
    public bool? Granted { get; init; }

    /// <summary>Free-form detail (e.g. a token-request justification or clarification text).</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// PS-side mission log seam (§Mission Log). Entries are appended in order; the
/// PS reads the log to evaluate whether each new request is consistent with the
/// mission's intent. The SDK provides the contract and an in-memory default
/// (<see cref="InMemoryMissionLog"/>).
/// </summary>
public interface IMissionLog
{
    /// <summary>Append <paramref name="entry"/> to the mission's ordered log.</summary>
    Task AppendAsync(MissionLogEntry entry, CancellationToken ct = default);

    /// <summary>Read the mission's entries in append order.</summary>
    Task<IReadOnlyList<MissionLogEntry>> ReadAsync(string s256, CancellationToken ct = default);

    /// <summary>
    /// Whether the mission already has a granted token entry for
    /// <paramref name="resource"/> and <paramref name="scope"/> — the prior-consent
    /// signal the PS uses to resolve a repeat request silently (§Agent Token
    /// Request — prior-consent gate).
    /// </summary>
    Task<bool> HasPriorConsentAsync(string s256, string resource, string scope, CancellationToken ct = default);
}
