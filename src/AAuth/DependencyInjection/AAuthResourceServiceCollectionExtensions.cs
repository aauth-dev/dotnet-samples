using System;
using System.Net.Http;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AAuth.DependencyInjection;

/// <summary>
/// Extension methods for registering AAuth resource server services via DI.
/// </summary>
public static class AAuthResourceServiceCollectionExtensions
{
    /// <summary>
    /// Register AAuth resource server services: verifier, key resolver,
    /// JTI store, and well-known metadata options.
    /// </summary>
    public static IServiceCollection AddAAuthResource(
        this IServiceCollection services,
        Action<AAuthResourceOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AAuthResourceOptions();
        configure(options);

        if (string.IsNullOrEmpty(options.Issuer))
            throw new InvalidOperationException("AAuthResourceOptions.Issuer must be set.");

        // Register AAuthVerifier as singleton.
        services.TryAddSingleton(sp => new AAuthVerifier
        {
            MaxAge = options.MaxSignatureAge,
        });

        // Register JwksClient (singleton) for key resolution.
        services.TryAddSingleton(sp =>
        {
            var httpClient = new HttpClient();
            return new JwksClient(httpClient);
        });

        // Register ISignatureKeyResolver.
        if (options.KeyResolver is not null)
        {
            services.TryAddSingleton(options.KeyResolver);
        }
        else
        {
            services.TryAddSingleton<ISignatureKeyResolver>(sp =>
            {
                var jwksClient = sp.GetRequiredService<JwksClient>();
                return new DefaultSignatureKeyResolver(jwksClient);
            });
        }

        // Register IJtiStore if replay detection is enabled.
        if (options.EnableReplayDetection)
        {
            services.TryAddSingleton<IJtiStore, InMemoryJtiStore>();
        }

        // Register the well-known metadata options for UseAAuthVerification / MapAAuthWellKnown.
        var metadataOptions = new AAuthResourceMetadataOptions
        {
            Issuer = options.Issuer,
            SigningKeys = options.SigningKeys,
            ClientName = options.ClientName,
            ScopeDescriptions = options.ScopeDescriptions,
        };
        services.TryAddSingleton(metadataOptions);

        return services;
    }
}
