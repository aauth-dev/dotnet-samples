using System;
using AAuth.Server;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for the resource-managed (two-party) interaction module.
/// </summary>
public static class AAuthResourceManagedServiceCollectionExtensions
{
    /// <summary>
    /// Register the resource-managed interaction seams: the opaque-token store
    /// (<see cref="IOpaqueTokenStore"/>) and the interaction pending store
    /// (<see cref="IInteractionPendingStore"/>), both in-memory by default and via
    /// <c>TryAdd</c> so the app may override either, plus
    /// <see cref="AAuthResourceManagedOptions"/>. A resource then opts a payload
    /// endpoint into interaction with <c>ctx.RequireAAuthInteraction(scope)</c> and
    /// maps the poll endpoint with <c>app.MapAAuthInteractionPoll()</c>; its consent
    /// page records the decision via <see cref="IInteractionPendingStore.Approve"/>.
    /// </summary>
    public static IServiceCollection AddAAuthResourceManaged(
        this IServiceCollection services,
        Action<AAuthResourceManagedOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AAuthResourceManagedOptions();
        configure(options);
        if (string.IsNullOrEmpty(options.ConsentUrl))
        {
            throw new InvalidOperationException("AAuthResourceManagedOptions.ConsentUrl must be set.");
        }

        services.TryAddSingleton(options);
        services.TryAddSingleton<IOpaqueTokenStore, InMemoryOpaqueTokenStore>();
        services.TryAddSingleton<IInteractionPendingStore, InMemoryInteractionPendingStore>();
        return services;
    }
}
