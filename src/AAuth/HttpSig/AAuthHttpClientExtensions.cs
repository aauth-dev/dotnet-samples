using System;
using System.Collections.Generic;
using System.Net.Http;
using AAuth.Crypto;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.HttpSig;

/// <summary>
/// Options for configuring an AAuth-signing <see cref="HttpClient"/> via DI.
/// </summary>
public sealed class AAuthClientOptions
{
    /// <summary>The agent's signing key (must have private component).</summary>
    public IAAuthKey Key { get; set; } = null!;

    /// <summary>The signing mode strategy.</summary>
    public ISignatureKeyProvider SigningMode { get; set; } = null!;

    /// <summary>Optional AAuth-Capabilities to declare on every request.</summary>
    public IReadOnlyList<string>? Capabilities { get; set; }
}

/// <summary>
/// Extension methods for registering AAuth-signing HTTP clients with
/// <see cref="IHttpClientFactory"/>.
/// </summary>
public static class AAuthHttpClientExtensions
{
    /// <summary>
    /// Register a named <see cref="HttpClient"/> that signs every outbound request.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The logical name for the client.</param>
    /// <param name="configure">Configure the signing key and mode.</param>
    /// <returns>The <see cref="IHttpClientBuilder"/> for further chaining.</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddAAuthClient("agent", options =>
    /// {
    ///     options.Key = key;
    ///     options.SigningMode = new HwkSignatureKeyProvider(key);
    /// });
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddAAuthClient(
        this IServiceCollection services,
        string name,
        Action<AAuthClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AAuthClientOptions();
        configure(options);

        if (options.Key is null)
            throw new InvalidOperationException("AAuthClientOptions.Key must be set.");
        if (options.SigningMode is null)
            throw new InvalidOperationException("AAuthClientOptions.SigningMode must be set.");

        return services.AddHttpClient(name)
            .AddHttpMessageHandler(() => new AAuthSigningHandler(options.Key, options.SigningMode)
            {
                Capabilities = options.Capabilities,
            });
    }
}
