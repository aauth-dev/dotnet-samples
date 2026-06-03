using System;
using System.Threading;
using AAuth;
using AAuth.Agent;
using AAuth.HttpSig;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering named AAuth agent HTTP clients via DI.
/// </summary>
public static class AAuthAgentServiceCollectionExtensions
{
    /// <summary>
    /// Register a named <see cref="System.Net.Http.HttpClient"/> configured as an
    /// AAuth agent with signing, optional challenge handling, and optional
    /// interaction handling. Resolve via <see cref="IHttpClientFactory.CreateClient(string)"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The logical name for the HttpClient (used with IHttpClientFactory).</param>
    /// <param name="configure">Configure the agent options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddAAuthAgent(
        this IServiceCollection services,
        string name,
        Action<AAuthAgentOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AAuthAgentOptions();
        configure(options);

        if (options.Key is null)
            throw new InvalidOperationException("AAuthAgentOptions.Key must be set.");

        services.AddHttpClient(name)
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var builder = new AAuthClientBuilder(options.Key);

                if (options.TokenRefresher is not null)
                {
                    builder.WithTokenRefresh(options.TokenRefresher);

                    if (options.PersonServer is not null)
                    {
                        builder.WithChallengeHandling(options.PersonServer, opts =>
                        {
                            opts.OnInteractionRequired = options.OnInteractionRequired;
                            opts.PollingTimeout = options.PollingTimeout;
                        });
                    }
                }
                else
                {
                    builder.UseHwk();
                }

                if (options.OnResourceInteraction is not null || options.OnApprovalPending is not null)
                {
                    builder.WithInteractionHandling(opts =>
                    {
                        opts.OnInteractionRequired = options.OnResourceInteraction;
                        opts.OnApprovalPending = options.OnApprovalPending;
                        opts.PollingTimeout = options.PollingTimeout;
                    });
                }

                return builder.BuildHandler();
            })
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);

        return services;
    }
}
