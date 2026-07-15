using System;
using AAuth.Identifiers;
using AAuth.Events.Agent;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Events.DependencyInjection;

/// <summary>Options for one-call AAuth Events agent registration.</summary>
public sealed class AAuthEventsAgentOptions
{
    /// <summary>Audience that event tokens must contain for this agent.</summary>
    public string? ExpectedAudience { get; set; }

    /// <summary>Application-owned local event context lookup.</summary>
    public IEventContextLookup? ContextLookup { get; set; }

    /// <summary>Optional application/durable deduplicator.</summary>
    public IEventDeduplicator? Deduplicator { get; set; }

    /// <summary>Capacity used by the convenience deduplicator when one is not supplied.</summary>
    public int InMemoryDeduplicatorCapacity { get; set; } = 10_000;

    /// <summary>Retention used by the convenience deduplicator when one is not supplied.</summary>
    public TimeSpan InMemoryDeduplicatorRetention { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Clock used by token and convenience-deduplicator validation.</summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>Allowed clock skew for event-token temporal claims.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional outbound Events URL trust policy.</summary>
    public IEventsUrlPolicy? UrlPolicy { get; set; }
}

/// <summary>Dependency-injection registration for the Events agent verifier.</summary>
public static class AAuthEventsAgentExtensions
{
    /// <summary>
    /// Registers discovery, event verification, and replay protection in one call.
    /// </summary>
    public static IServiceCollection AddAAuthEventsAgent(
        this IServiceCollection services,
        Action<AAuthEventsAgentOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new AAuthEventsAgentOptions();
        configure(options);
        Validate(options);

        services.AddSingleton(options);
        services.AddSingleton<IEventsUrlPolicy>(
            options.UrlPolicy ?? new DefaultEventsUrlPolicy());
        services.AddSingleton<IEventContextLookup>(
            options.ContextLookup ?? throw new InvalidOperationException(
                "An application-owned event context lookup is required."));
        services.AddSingleton<IEventDeduplicator>(
            options.Deduplicator ?? new InMemoryEventDeduplicator(
                options.InMemoryDeduplicatorCapacity,
                options.InMemoryDeduplicatorRetention,
                options.Clock));
        services.AddSingleton(new TokenVerifier
        {
            Clock = options.Clock ?? (() => DateTimeOffset.UtcNow),
            ClockSkew = options.ClockSkew,
        });
        services.AddHttpClient<EventsJwtKeyResolver>();
        services.AddSingleton<EventTokenVerifier>(serviceProvider =>
        {
            var configured = serviceProvider.GetRequiredService<AAuthEventsAgentOptions>();
            return new EventTokenVerifier(
                serviceProvider.GetRequiredService<EventsJwtKeyResolver>(),
                configured.ExpectedAudience!,
                serviceProvider.GetRequiredService<IEventContextLookup>(),
                serviceProvider.GetRequiredService<IEventDeduplicator>());
        });
        return services;
    }

    /// <summary>Convenience overload for the required audience and context lookup.</summary>
    public static IServiceCollection AddAAuthEventsAgent(
        this IServiceCollection services,
        string expectedAudience,
        IEventContextLookup contextLookup,
        Action<AAuthEventsAgentOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(contextLookup);
        return services.AddAAuthEventsAgent(options =>
        {
            options.ExpectedAudience = expectedAudience;
            options.ContextLookup = contextLookup;
            configure?.Invoke(options);
        });
    }

    private static void Validate(AAuthEventsAgentOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ExpectedAudience))
            throw new ArgumentException(
                "ExpectedAudience is required.", nameof(options.ExpectedAudience));
        if (!AgentId.TryParse(options.ExpectedAudience, out _, out var audienceError))
            throw new ArgumentException(
                $"ExpectedAudience must be a valid AAuth agent identifier: {audienceError}",
                nameof(options.ExpectedAudience));
        if (options.ContextLookup is null)
            throw new ArgumentException(
                "ContextLookup is required.", nameof(options.ContextLookup));
        if (options.InMemoryDeduplicatorCapacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(options.InMemoryDeduplicatorCapacity));
        if (options.InMemoryDeduplicatorRetention <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options.InMemoryDeduplicatorRetention));
        if (options.ClockSkew < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options.ClockSkew));
    }
}
