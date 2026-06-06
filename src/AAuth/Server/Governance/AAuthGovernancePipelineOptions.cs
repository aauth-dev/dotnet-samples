using System;

namespace AAuth.Server.Governance;

/// <summary>
/// Options for the PS governance endpoint mapper (<c>MapAAuthGovernance</c>).
/// Controls the route prefix and the per-endpoint paths so a PS can mount the
/// permission / audit / interaction endpoints where its metadata advertises them
/// (§Person Server Metadata, §PS Governance Endpoints).
/// </summary>
public sealed class AAuthGovernancePipelineOptions
{
    /// <summary>
    /// Route prefix prepended to each endpoint path (default empty). For example,
    /// set <c>"/governance"</c> to mount at <c>/governance/permission</c>.
    /// </summary>
    public string RoutePrefix { get; set; } = string.Empty;

    /// <summary>The permission endpoint path (§Permission Endpoint). Default <c>/permission</c>.</summary>
    public string PermissionPath { get; set; } = "/permission";

    /// <summary>The audit endpoint path (§Audit Endpoint). Default <c>/audit</c>.</summary>
    public string AuditPath { get; set; } = "/audit";

    /// <summary>The interaction endpoint path (§Interaction Endpoint). Default <c>/mission-interaction</c>.</summary>
    public string InteractionPath { get; set; } = "/mission-interaction";

    /// <summary>The mission-creation endpoint path (§Mission Creation). Default <c>/mission</c>.</summary>
    public string MissionPath { get; set; } = "/mission";

    /// <summary>
    /// The deferred-consent poll endpoint path template (§Deferred Consent). The
    /// mapper appends <c>/{id}</c>. Default <c>/governance-pending</c>; the
    /// <c>202</c> <c>Location</c> points the agent here.
    /// </summary>
    public string PendingPath { get; set; } = "/governance-pending";

    /// <summary>
    /// Optional user-facing interaction URL (§User Interaction). When set, the
    /// <c>202</c> deferred-consent response includes an
    /// <c>AAuth-Requirement: requirement=interaction</c> header pointing the
    /// agent's user here (the PS's browser consent page). When null, the agent
    /// relies on polling the <c>Location</c> alone.
    /// </summary>
    public string? InteractionUrl { get; set; }

    /// <summary>
    /// The PS's canonical approver URL written into mission approval blobs
    /// (§Mission Approval). When null, the mapper derives it from the request
    /// origin (<c>scheme://host</c>). Set this when the PS's advertised issuer
    /// differs from the request origin (e.g. behind a proxy).
    /// </summary>
    public string? Approver { get; set; }

    // Compose the prefix with a path, collapsing duplicate slashes at the seam.
    internal string Resolve(string path)
    {
        if (string.IsNullOrEmpty(RoutePrefix))
        {
            return path;
        }
        var prefix = RoutePrefix.TrimEnd('/');
        var suffix = path.StartsWith('/') ? path : "/" + path;
        return prefix + suffix;
    }
}
