using AAuth.Events.AgentProvider;
using AAuth.Events.Http;
using AAuth.Events;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Options registered by the Events Agent Provider integration.</summary>
public sealed class AAuthEventsAgentProviderOptions
{
    /// <summary>Resolver used by mapped event endpoints.</summary>
    public EventsJwtKeyResolver? JwtKeyResolver { get; set; }
    /// <summary>HTTP verifier used by mapped event endpoints.</summary>
    public EventsHttpMessageVerifier? HttpMessageVerifier { get; set; }
    /// <summary>Default endpoint route pattern for application composition.</summary>
    public string EndpointPattern { get; set; } = "/events";
    /// <summary>Maximum event payload size when a verifier is created by the mapper.</summary>
    public int MaxBodyBytes { get; set; } = AAuthEventsConstants.DefaultMaxBodyBytes;
    /// <summary>Receipt clock used by mapped endpoints.</summary>
    public Func<DateTimeOffset> Clock { get; set; } = static () => DateTimeOffset.UtcNow;
}

/// <summary>DI registration for the durable Events Agent Provider role.</summary>
public static class AAuthEventsAgentProviderExtensions
{
    /// <summary>
    /// Registers the Agent Provider role. An application store must already be
    /// registered; no process-local production store is supplied.
    /// </summary>
    public static IServiceCollection AddAAuthEventsAgentProvider(
        this IServiceCollection services,
        Action<AAuthEventsAgentProviderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!services.Any(d => d.ServiceType == typeof(IAAuthAgentProviderEventStore)))
            throw new InvalidOperationException(
                "AddAAuthEventsAgentProvider requires an application-provided IAAuthAgentProviderEventStore.");

        var options = new AAuthEventsAgentProviderOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        if (options.JwtKeyResolver is not null)
            services.TryAddSingleton(options.JwtKeyResolver);
        if (options.HttpMessageVerifier is not null)
            services.TryAddSingleton(options.HttpMessageVerifier);
        return services;
    }

    /// <summary>Registers a durable store and the Agent Provider role in one call.</summary>
    public static IServiceCollection AddAAuthEventsAgentProvider(
        this IServiceCollection services,
        IAAuthAgentProviderEventStore store,
        Action<AAuthEventsAgentProviderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        services.AddSingleton(store);
        return services.AddAAuthEventsAgentProvider(configure);
    }

    /// <summary>Short alias for <see cref="AddAAuthEventsAgentProvider(IServiceCollection, Action{AAuthEventsAgentProviderOptions}?)"/>.</summary>
    public static IServiceCollection AddAAuthAgentProvider(
        this IServiceCollection services,
        Action<AAuthEventsAgentProviderOptions>? configure = null) =>
        services.AddAAuthEventsAgentProvider(configure);

    /// <summary>Short alias accepting the required durable store.</summary>
    public static IServiceCollection AddAAuthAgentProvider(
        this IServiceCollection services,
        IAAuthAgentProviderEventStore store,
        Action<AAuthEventsAgentProviderOptions>? configure = null) =>
        services.AddAAuthEventsAgentProvider(store, configure);
}
