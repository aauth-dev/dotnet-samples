using System;

namespace AAuth.Server;

/// <summary>
/// Options for the resource-managed (two-party) interaction module registered by
/// <c>AddAAuthResourceManaged</c>.
/// </summary>
public sealed class AAuthResourceManagedOptions
{
    /// <summary>
    /// Absolute HTTPS URL of the resource's own consent page, advertised as the
    /// interaction <c>url</c>. MUST NOT contain a query or fragment
    /// (§Interaction Required).
    /// </summary>
    public string ConsentUrl { get; set; } = null!;

    /// <summary>
    /// Poll path prefix for the deferred-response <c>Location</c>. Default
    /// <c>/pending</c>. <c>MapAAuthInteractionPoll</c> serves
    /// <c>{PollPath}/{code}</c> from this value.
    /// </summary>
    public string PollPath { get; set; } = "/pending";

    /// <summary>Lifetime of an issued opaque access token. Default 30 minutes.</summary>
    public TimeSpan TokenTtl { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Lifetime of a pending interaction code. Default 10 minutes.</summary>
    public TimeSpan CodeTtl { get; set; } = TimeSpan.FromMinutes(10);
}
