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
        ValidateConsentUrl(options.ConsentUrl);

        services.TryAddSingleton(options);
        services.TryAddSingleton<IOpaqueTokenStore, InMemoryOpaqueTokenStore>();
        services.TryAddSingleton<IInteractionPendingStore, InMemoryInteractionPendingStore>();
        return services;
    }

    // §Interaction Required (spec, #interaction-required / #ps-interaction-relay):
    // the interaction `url` MUST be an absolute HTTPS URL (loopback http allowed
    // for development) and MUST NOT carry a query or fragment — the poll/callback
    // machinery appends `?code=…`. Validate at registration so a misconfigured
    // resource fails fast instead of advertising an unsafe/malformed consent URL.
    private static void ValidateConsentUrl(string? consentUrl)
    {
        if (string.IsNullOrEmpty(consentUrl))
        {
            throw new InvalidOperationException("AAuthResourceManagedOptions.ConsentUrl must be set.");
        }
        if (!Uri.TryCreate(consentUrl, UriKind.Absolute, out var uri)
            || !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
        {
            throw new InvalidOperationException(
                "AAuthResourceManagedOptions.ConsentUrl must be an absolute https URL " +
                "(loopback http allowed for development).");
        }
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "AAuthResourceManagedOptions.ConsentUrl must not contain a query or fragment.");
        }
    }
}
