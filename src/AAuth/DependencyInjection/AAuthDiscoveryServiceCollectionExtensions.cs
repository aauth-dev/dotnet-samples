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
        {
            var http = new HttpClient();
            return new MetadataClient(http, options.MetadataCacheTtl);
        });

        services.TryAddSingleton(sp =>
        {
            var http = new HttpClient();
            return new JwksClient(http, options.JwksCacheTtl, options.JwksMinRefreshInterval);
        });

        return services;
    }
}
