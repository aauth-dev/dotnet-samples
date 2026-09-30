using AAuth;
using AAuth.Access;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Configures one named Access Server instance registered by
/// <see cref="AAuthAccessServerServiceCollectionExtensions.AddAAuthAccessServer(IServiceCollection, string?, Action{AAuthAccessServerOptions}?)"/>.
/// Each seam resolves, in order, from the builder's <c>Use*</c> helper, an unkeyed DI
/// registration, then the SDK default. The access policy has no default.
/// </summary>
public sealed class AAuthAccessServerBuilder
{
    /// <summary>The instance name used when none is given.</summary>
    public const string DefaultName = "AccessServer";

    internal AAuthAccessServerBuilder(IServiceCollection services, string name)
    {
        Services = services;
        Name = name;
    }

    /// <summary>The service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>The instance name; seams and the <see cref="IAAuthServerIdentity"/> are keyed by it.</summary>
    public string Name { get; }

    /// <summary>Configure the instance's options.</summary>
    public AAuthAccessServerBuilder Configure(Action<AAuthAccessServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(Name, configure);
        return this;
    }

    /// <summary>Configure the instance's trust rules (<see cref="AAuthAccessServerOptions.Trust"/>).</summary>
    public AAuthAccessServerBuilder WithTrust(Action<AAuthTrustOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return Configure(options => configure(options.Trust));
    }

    /// <summary>Use <typeparamref name="T"/> as the allow/deny/defer decision.</summary>
    public AAuthAccessServerBuilder UsePolicy<T>() where T : class, IAccessPolicy => Use<IAccessPolicy, T>();

    /// <inheritdoc cref="UsePolicy{T}()"/>
    public AAuthAccessServerBuilder UsePolicy(IAccessPolicy policy) => Use(policy);

    /// <inheritdoc cref="UsePolicy{T}()"/>
    public AAuthAccessServerBuilder UsePolicy(Func<IServiceProvider, IAccessPolicy> factory) => Use(factory);

    /// <summary>Replace the pending store (default <see cref="InMemoryAccessPendingStore"/>).</summary>
    public AAuthAccessServerBuilder UsePendingStore<T>() where T : class, IAccessPendingStore => Use<IAccessPendingStore, T>();

    /// <inheritdoc cref="UsePendingStore{T}()"/>
    public AAuthAccessServerBuilder UsePendingStore(IAccessPendingStore store) => Use(store);

    /// <inheritdoc cref="UsePendingStore{T}()"/>
    public AAuthAccessServerBuilder UsePendingStore(Func<IServiceProvider, IAccessPendingStore> factory) => Use(factory);

    /// <summary>Replace the token verifier (default: the instance's egress policy and time provider).</summary>
    public AAuthAccessServerBuilder UseTokenVerifier(TokenVerifier verifier) => Use(verifier);

    /// <summary>Replace the token inventory (default <see cref="InMemoryJtiStore"/>).</summary>
    public AAuthAccessServerBuilder UseTokenInventory<T>() where T : class, IJtiStore => Use<IJtiStore, T>();

    /// <inheritdoc cref="UseTokenInventory{T}()"/>
    public AAuthAccessServerBuilder UseTokenInventory(IJtiStore inventory) => Use(inventory);

    private AAuthAccessServerBuilder Use<TService, TImplementation>()
        where TService : class where TImplementation : class, TService
    {
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton<TService, TImplementation>(Name));
        return this;
    }

    private AAuthAccessServerBuilder Use<TService>(TService instance) where TService : class
    {
        ArgumentNullException.ThrowIfNull(instance);
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton(Name, instance));
        return this;
    }

    private AAuthAccessServerBuilder Use<TService>(Func<IServiceProvider, TService> factory) where TService : class
    {
        ArgumentNullException.ThrowIfNull(factory);
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton<TService>(Name, (sp, _) => factory(sp)));
        return this;
    }
}

/// <summary>Registers AAuth Access Server instances.</summary>
public static class AAuthAccessServerServiceCollectionExtensions
{
    /// <summary>The configuration section an Access Server binds from by default.</summary>
    public const string ConfigurationSection = "AAuth:AccessServer";

    /// <summary>
    /// Register an Access Server instance. Map it with <c>app.MapAAuthAccessServer(name)</c>.
    /// Validated at startup: a missing issuer, signing key or <see cref="IAccessPolicy"/> fails fast.
    /// </summary>
    public static AAuthAccessServerBuilder AddAAuthAccessServer(this IServiceCollection services, string? name = null,
        Action<AAuthAccessServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        name ??= AAuthAccessServerBuilder.DefaultName;
        var builder = new AAuthAccessServerBuilder(services, name);
        var options = services.AddValidatedAAuthOptions<AAuthAccessServerOptions, AccessServerOptionsValidator>(name);
        if (configure is not null) options.Configure(configure);

        services.AddAAuthDiscovery();
        services.TryAddSingleton<AAuth.HttpSig.AAuthVerifier>();
        services.TryAddKeyedSingleton<IAAuthServerIdentity>(name, (sp, key) =>
        {
            var instance = (string)key!;
            var value = sp.GetRequiredService<IOptionsMonitor<AAuthAccessServerOptions>>().Get(instance);
            AAuthServerRoles.LoadKeyHandle(value.SigningKeys, value.KeyHandle, value.KeyId, sp, nameof(AAuthAccessServerOptions));
            return new AAuthServerIdentity(instance, value.Issuer, AuthTokenBuilder.AccessDwk, value.SigningKeys, value.EgressPolicy);
        });
        services.TryAddKeyedSingleton<IAccessPolicy>(name, (sp, key) => sp.GetService<IAccessPolicy>()
            ?? throw new InvalidOperationException($"Access Server '{key}' requires an IAccessPolicy: call UsePolicy or register one."));
        services.TryAddKeyedSingleton<IAccessPendingStore>(name, (sp, _) =>
            sp.GetService<IAccessPendingStore>() ?? new InMemoryAccessPendingStore());
        services.TryAddKeyedSingleton<TokenVerifier>(name, (sp, key) =>
        {
            if (sp.GetService<TokenVerifier>() is { } shared) return shared;
            var value = sp.GetRequiredService<IOptionsMonitor<AAuthAccessServerOptions>>().Get((string)key!);
            return new TokenVerifier { EgressPolicy = value.EgressPolicy, TimeProvider = value.TimeProvider };
        });
        services.TryAddKeyedSingleton<IJtiStore>(name, (sp, key) => sp.GetService<IJtiStore>()
            ?? new InMemoryJtiStore(sp.GetRequiredService<IOptionsMonitor<AAuthAccessServerOptions>>().Get((string)key!).TimeProvider));
        return builder;
    }

    /// <summary>Register an Access Server instance bound from <paramref name="configuration"/> (for example <c>AAuth:AccessServer</c>).</summary>
    public static AAuthAccessServerBuilder AddAAuthAccessServer(this IServiceCollection services, IConfiguration configuration,
        string? name = null, Action<AAuthAccessServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var builder = services.AddAAuthAccessServer(name, configure: null);
        services.AddOptions<AAuthAccessServerOptions>(builder.Name).Bind(configuration);
        if (configure is not null) builder.Configure(configure);
        return builder;
    }
}

internal sealed class AccessServerOptionsValidator(IServiceProvider services) : AAuthOptionsValidator<AAuthAccessServerOptions>
{
    protected override void Validate(string? name, AAuthAccessServerOptions options, List<string> failures)
    {
        // The issuer is the auth-token iss/aud anchor; the login path is appended with
        // `?code=…`; each trusted Person Server is a four-party anchor.
        if (!AAuthUrl.IsHttpsOrLoopback(options.Issuer, options.EgressPolicy))
            failures.Add("AAuthAccessServerOptions.Issuer must be an absolute https URL (loopback http allowed for development).");
        if (options.SigningKeys.Count == 0 && string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("AAuthAccessServerOptions needs a signing key: add one to SigningKeys or set KeyHandle.");
        if (options.InteractionLoginPath.Contains('?') || options.InteractionLoginPath.Contains('#'))
            failures.Add("AAuthAccessServerOptions.InteractionLoginPath must not contain a query or fragment.");
        foreach (var trustedPs in options.Trust.PersonServers.Allowed ?? new HashSet<string>())
        {
            if (!AAuthUrl.IsHttpsOrLoopback(trustedPs, options.EgressPolicy))
                failures.Add($"AAuthAccessServerOptions.Trust.PersonServers entry '{trustedPs}' must be an absolute https URL " +
                    "(loopback http allowed for development).");
        }
        if (!HasPolicy(name ?? Microsoft.Extensions.Options.Options.DefaultName))
            failures.Add($"Access Server '{name}' requires an IAccessPolicy: call UsePolicy on its builder or register one in DI.");
    }

    // The keyed default forwards to an unkeyed policy and throws when there is none.
    private bool HasPolicy(string name)
    {
        try
        {
            return services.GetKeyedService<IAccessPolicy>(name) is not null;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
