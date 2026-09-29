using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AAuth;

/// <summary>
/// Shape-only startup validation for an SDK options type. Async concerns (loading a
/// key from a store, fetching metadata) fail at first use with a clear error instead.
/// </summary>
internal abstract class AAuthOptionsValidator<TOptions> : IValidateOptions<TOptions>
    where TOptions : class
{
    public ValidateOptionsResult Validate(string? name, TOptions options)
    {
        var failures = new List<string>();
        Validate(name, options, failures);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    protected abstract void Validate(string? name, TOptions options, List<string> failures);
}

internal static class AAuthOptionsRegistration
{
    /// <summary>
    /// The registration convention for AAuth role options: named options with their
    /// validator, checked when the host starts.
    /// </summary>
    public static OptionsBuilder<TOptions> AddValidatedAAuthOptions<TOptions, TValidator>(
        this IServiceCollection services, string name)
        where TOptions : class
        where TValidator : class, IValidateOptions<TOptions>
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<TOptions>, TValidator>());
        return services.AddOptions<TOptions>(name).ValidateOnStart();
    }
}
