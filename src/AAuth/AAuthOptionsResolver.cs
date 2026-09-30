using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AAuth;

/// <summary>
/// Builds a fresh options instance from a seed and every DI configuration of
/// <typeparamref name="TOptions"/> (default name), for pipelines that also take a
/// per-call configure delegate.
/// </summary>
internal static class AAuthOptionsResolver
{
    public static TOptions Create<TOptions>(IServiceProvider services, Func<TOptions> seed) where TOptions : class
    {
        var options = seed();
        foreach (var setup in services.GetServices<IConfigureOptions<TOptions>>())
        {
            if (setup is IConfigureNamedOptions<TOptions> named) named.Configure(Options.DefaultName, options);
            else setup.Configure(options);
        }
        foreach (var post in services.GetServices<IPostConfigureOptions<TOptions>>())
            post.PostConfigure(Options.DefaultName, options);
        return options;
    }
}
