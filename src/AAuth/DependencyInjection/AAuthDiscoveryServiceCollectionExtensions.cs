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
            new MetadataClient(CreateDiscoveryHttpClient(), options.MetadataCacheTtl));

        services.TryAddSingleton(sp =>
            new JwksClient(CreateDiscoveryHttpClient(), options.JwksCacheTtl, options.JwksMinRefreshInterval));

        return services;
    }

    // The discovery clients are singletons that hold their HttpClient for the
    // app lifetime, so a SocketsHttpHandler with a bounded PooledConnectionLifetime
    // keeps connections (and DNS) rotating without an IHttpClientFactory — the SDK
    // owns this so consumers register no HttpClient plumbing.
    private static HttpClient CreateDiscoveryHttpClient() =>
        new(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(2) });
}
