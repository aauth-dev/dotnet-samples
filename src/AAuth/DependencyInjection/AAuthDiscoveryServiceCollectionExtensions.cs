using System;
using System.Net.Http;
using AAuth;
using AAuth.Discovery;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering shared AAuth discovery clients in DI.
/// </summary>
public static class AAuthDiscoveryServiceCollectionExtensions
{
    /// <summary>
    /// Register shared singleton <see cref="MetadataClient"/> and <see cref="JwksClient"/>
    /// for use by agent and resource DI extensions.
    /// </summary>
    public static IServiceCollection AddAAuthDiscovery(
        this IServiceCollection services,
        Action<AAuthDiscoveryOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new AAuthDiscoveryOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(sp =>
            new MetadataClient(cacheTtl: options.MetadataCacheTtl, policy: options.EgressPolicy,
                maxCacheEntries: options.MaxCacheEntries, maxCacheAge: options.MaxCacheAge));

        services.TryAddSingleton(sp =>
            new JwksClient(cacheTtl: options.JwksCacheTtl, minRefreshInterval: options.JwksMinRefreshInterval,
                policy: options.EgressPolicy, maxCacheEntries: options.MaxCacheEntries, maxCacheAge: options.MaxCacheAge));

        return services;
    }

}
