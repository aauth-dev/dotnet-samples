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
