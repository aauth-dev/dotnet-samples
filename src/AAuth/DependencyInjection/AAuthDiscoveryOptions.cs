using System;

namespace AAuth;

/// <summary>
/// Options for configuring shared discovery clients in DI.
/// </summary>
public sealed class AAuthDiscoveryOptions
{
    /// <summary>Metadata cache TTL. Default: 5 minutes.</summary>
    public TimeSpan MetadataCacheTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>JWKS cache TTL. Default: 1 hour.</summary>
    public TimeSpan JwksCacheTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Minimum interval between JWKS fetches for the same URI.
    /// Per spec, this must be at least 1 minute. Default: 1 minute.
    /// </summary>
    public TimeSpan JwksMinRefreshInterval { get; set; } = TimeSpan.FromMinutes(1);
}
