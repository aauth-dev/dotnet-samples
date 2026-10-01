using System;
using System.Collections.Generic;
using System.Net.Http;
using AAuth.Crypto;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AAuth.HttpSig;

/// <summary>
/// Options for a generic Signature Keys <see cref="HttpClient"/> registered with <c>AddAAuthClient(name)</c>.
/// Named by client; validated when the host starts.
/// </summary>
public sealed class AAuthClientOptions
{
    /// <summary>The handle of the signing key in the registered <see cref="IKeyStore"/>.</summary>
    public string? KeyHandle { get; set; }

    /// <summary>Code-only: the signing key, instead of <see cref="KeyHandle"/>.</summary>
    public IAAuthSigner? Signer { get; set; }

    /// <summary>Code-only: the Signature Keys scheme.</summary>
    public ISignatureKeyProvider? SignatureKeyProvider { get; set; }

    /// <summary>Optional AAuth-Capabilities to declare on every request.</summary>
    public string[]? Capabilities { get; set; }
}

/// <summary>
/// Extension methods for registering AAuth-signing HTTP clients with
/// <see cref="IHttpClientFactory"/>.
/// </summary>
public static class AAuthHttpClientExtensions
{
    /// <summary>
    /// Register a named <see cref="HttpClient"/> that signs every outbound request with a generic
    /// Signature Keys scheme. For AAuth agents use <c>AddAAuthAgent</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddAAuthClient("signer", options =>
    /// {
    ///     options.Signer = key;
    ///     options.SignatureKeyProvider = new HwkSignatureKeyProvider(key);
    /// });
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddAAuthClient(this IServiceCollection services, string name,
        Action<AAuthClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddValidatedAAuthOptions<AAuthClientOptions, AAuthClientOptionsValidator>(name).Configure(configure);
        return services.AddHttpClient(name)
            .AddHttpMessageHandler(sp =>
            {
                var options = sp.GetRequiredService<IOptionsMonitor<AAuthClientOptions>>().Get(name);
                var signer = options.Signer ?? (sp.GetService<IKeyStore>() ?? FileKeyStore.Default())
                    .LoadAsync(options.KeyHandle!).GetAwaiter().GetResult()
                    ?? throw new InvalidOperationException($"AAuthClientOptions.KeyHandle '{options.KeyHandle}' was not found in the key store.");
                return new AAuthSigningHandler(signer, options.SignatureKeyProvider!) { Capabilities = options.Capabilities };
            });
    }
}

internal sealed class AAuthClientOptionsValidator : AAuthOptionsValidator<AAuthClientOptions>
{
    protected override void Validate(string? name, AAuthClientOptions options, List<string> failures)
    {
        if ((options.Signer is null) == string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("Set exactly one of Signer and KeyHandle.");
        if (options.SignatureKeyProvider is null)
            failures.Add("Set SignatureKeyProvider.");
    }
}
