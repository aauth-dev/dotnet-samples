using System;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth;

/// <summary>
/// Resolves a replaceable seam in the SDK's precedence order (after any
/// per-request or per-endpoint override): an explicit instance, a DI service keyed
/// by the role instance name, an unkeyed DI service, then the default built from data.
/// Keyed DI does not fall back to unkeyed registrations on its own, so this does.
/// </summary>
internal static class AAuthSeams
{
    public static T Resolve<T>(IServiceProvider services, string? name, T? explicitInstance, Func<T> fallback)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(fallback);
        return explicitInstance
            ?? (name is null ? null : (services as IKeyedServiceProvider)?.GetKeyedService<T>(name))
            ?? services.GetService<T>()
            ?? fallback();
    }
}
