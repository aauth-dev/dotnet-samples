using System;
using AAuth;
using AAuth.Agent.Governance;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering an <see cref="AAuthGovernanceClient"/> via DI,
/// so agents can resolve a configured governance client (mission / permission /
/// audit / interaction) instead of constructing one inline. Mirrors
/// <see cref="AAuthAgentServiceCollectionExtensions.AddAAuthAgent"/>.
/// </summary>
public static class AAuthGovernanceClientServiceCollectionExtensions
{
    /// <summary>
    /// Register a singleton <see cref="AAuthGovernanceClient"/> produced by
    /// <paramref name="factory"/>. The factory typically builds the client from a
    /// configured <see cref="AAuthClientBuilder"/> via
    /// <see cref="AAuthClientBuilder.BuildGovernance()"/>, binding the agent
    /// identity, signing mode, and Person Server.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="factory">Factory that builds the governance client from the service provider.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddAAuthGovernanceClient(
        this IServiceCollection services,
        Func<IServiceProvider, AAuthGovernanceClient> factory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddSingleton(factory);
        return services;
    }

    /// <summary>
    /// Register a singleton <see cref="AAuthGovernanceClient"/> built from an
    /// <see cref="AAuthClientBuilder"/> configured by <paramref name="configureBuilder"/>.
    /// The builder MUST set a signing mode; bind a Person Server via
    /// <see cref="AAuthClientBuilder.WithPersonServer"/> to enable mission sessions.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureBuilder">Configures the client builder (signing mode, PS, etc.).</param>
    /// <param name="defaultOptions">Default governance options applied when a call omits its own.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddAAuthGovernanceClient(
        this IServiceCollection services,
        Func<IServiceProvider, AAuthClientBuilder> configureBuilder,
        GovernanceOptions? defaultOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureBuilder);
        return services.AddAAuthGovernanceClient(
            sp => configureBuilder(sp).BuildGovernance(defaultOptions));
    }
}
