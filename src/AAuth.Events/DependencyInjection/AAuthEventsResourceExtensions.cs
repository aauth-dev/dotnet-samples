using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Options for one-call Events resource registration.</summary>
public sealed class AAuthEventsResourceOptions
{
    /// <summary>Optional preconfigured low-level resolver.</summary>
    public EventsJwtKeyResolver? KeyResolver { get; set; }
    /// <summary>Optional URL trust policy for the default resolver.</summary>
    public IEventsUrlPolicy? UrlPolicy { get; set; }
    /// <summary>Maximum registration body size.</summary>
    public int MaxBodyBytes { get; set; } = AAuthEventsConstants.DefaultMaxBodyBytes;
    /// <summary>Signature age accepted by registration endpoints.</summary>
    public TimeSpan SignatureMaxAge { get; set; } = TimeSpan.FromSeconds(60);
    /// <summary>Allowed future signature skew.</summary>
    public TimeSpan SignatureFutureSkew { get; set; } = TimeSpan.FromSeconds(5);
}

/// <summary>Registers AAuth Events resource subscription services.</summary>
public static class AAuthEventsResourceExtensions
{
    /// <summary>
    /// Registers the Events discovery clients, subscribe-token resolver, HTTP
    /// verifier, and subscription registration verifier in one call.
    /// </summary>
    public static IServiceCollection AddAAuthEventsResource(
        this IServiceCollection services,
        Action<AAuthEventsResourceOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = new AAuthEventsResourceOptions();
        configure?.Invoke(options);
        if (options.MaxBodyBytes < 0) throw new ArgumentOutOfRangeException(nameof(options.MaxBodyBytes));

        services.AddAAuthDiscovery();
        services.TryAddSingleton(sp => options.KeyResolver ?? new EventsJwtKeyResolver(
            sp.GetRequiredService<MetadataClient>(),
            sp.GetRequiredService<JwksClient>(),
            options.UrlPolicy ?? new DefaultEventsUrlPolicy()));
        services.TryAddSingleton(sp => new EventsHttpMessageVerifier
        {
            MaxAge = options.SignatureMaxAge,
            FutureSkew = options.SignatureFutureSkew,
            MaxBodyBytes = options.MaxBodyBytes,
        });
        services.TryAddSingleton<SubscriptionRegistrationVerifier>();
        return services;
    }

    /// <summary>Alias for <see cref="AddAAuthEventsResource"/>.</summary>
    public static IServiceCollection AddAAuthEventsSubscriptions(
        this IServiceCollection services,
        Action<AAuthEventsResourceOptions>? configure = null) =>
        services.AddAAuthEventsResource(configure);
}
