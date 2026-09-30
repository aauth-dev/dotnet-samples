using AAuth;
using AAuth.Access;
using AAuth.Discovery;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Governance;
using AAuth.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Configures one named Person Server instance registered by
/// <see cref="AAuthPersonServerServiceCollectionExtensions.AddAAuthPersonServer(IServiceCollection, string?, Action{AAuthPersonServerOptions}?)"/>.
/// Each seam resolves, in order, from the builder's <c>Use*</c> helper, an unkeyed DI
/// registration, then the SDK default.
/// </summary>
public sealed class AAuthPersonServerBuilder
{
    /// <summary>The instance name used when none is given.</summary>
    public const string DefaultName = "PersonServer";

    /// <summary>The named <see cref="IHttpClientFactory"/> client the PS→AS federation transport uses.</summary>
    public const string FederationHttpClientName = "aauth-federation";

    internal AAuthPersonServerBuilder(IServiceCollection services, string name)
    {
        Services = services;
        Name = name;
    }

    /// <summary>The service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>The instance name; seams and the <see cref="IAAuthServerIdentity"/> are keyed by it.</summary>
    public string Name { get; }

    /// <summary>Configure the instance's options.</summary>
    public AAuthPersonServerBuilder Configure(Action<AAuthPersonServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(Name, configure);
        return this;
    }

    /// <summary>Configure the instance's trust rules (<see cref="AAuthPersonServerOptions.Trust"/>).</summary>
    public AAuthPersonServerBuilder WithTrust(Action<AAuthTrustOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return Configure(options => configure(options.Trust));
    }

    /// <summary>Replace the pending store (default <see cref="InMemoryPersonPendingStore"/>).</summary>
    public AAuthPersonServerBuilder UsePendingStore<T>() where T : class, IPersonPendingStore => Use<IPersonPendingStore, T>();

    /// <inheritdoc cref="UsePendingStore{T}()"/>
    public AAuthPersonServerBuilder UsePendingStore(IPersonPendingStore store) => Use(store);

    /// <inheritdoc cref="UsePendingStore{T}()"/>
    public AAuthPersonServerBuilder UsePendingStore(Func<IServiceProvider, IPersonPendingStore> factory) => Use(factory);

    /// <summary>Replace the identity and consent decision (default <see cref="DefaultIdentityClaimsAsserter"/>).</summary>
    public AAuthPersonServerBuilder UseClaimsAsserter<T>() where T : class, IIdentityClaimsAsserter => Use<IIdentityClaimsAsserter, T>();

    /// <inheritdoc cref="UseClaimsAsserter{T}()"/>
    public AAuthPersonServerBuilder UseClaimsAsserter(IIdentityClaimsAsserter asserter) => Use(asserter);

    /// <inheritdoc cref="UseClaimsAsserter{T}()"/>
    public AAuthPersonServerBuilder UseClaimsAsserter(Func<IServiceProvider, IIdentityClaimsAsserter> factory) => Use(factory);

    /// <summary>Replace the token verifier (default: the instance's egress policy and time provider).</summary>
    public AAuthPersonServerBuilder UseTokenVerifier(TokenVerifier verifier) => Use(verifier);

    /// <summary>Replace the token inventory (default <see cref="InMemoryJtiStore"/>).</summary>
    public AAuthPersonServerBuilder UseTokenInventory<T>() where T : class, IJtiStore => Use<IJtiStore, T>();

    /// <inheritdoc cref="UseTokenInventory{T}()"/>
    public AAuthPersonServerBuilder UseTokenInventory(IJtiStore inventory) => Use(inventory);

    /// <summary>
    /// Enable four-party PS→AS federation. The PS signs token requests as itself
    /// (<c>jwks_uri</c> scheme, active key) through the named
    /// <see cref="FederationHttpClientName"/> client.
    /// </summary>
    public AAuthPersonServerBuilder WithFederation()
    {
        Services.AddOptions<AAuthFederationOptions>();
        Services.AddHttpClient(FederationHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp => AAuthHttpTransport.CreateHandler(sp.GetRequiredService<MetadataClient>().Policy));
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton<AccessServerClient>(Name, (sp, key) =>
        {
            var metadata = sp.GetRequiredService<MetadataClient>();
            var transport = sp.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(FederationHttpClientName);
            var contract = sp.GetRequiredService<IOptions<AAuthFederationOptions>>().Value.TransportContract;
            if (contract is null)
            {
                transport = AAuthHttpTransport.BorrowEnforcingHandler(transport, metadata.Policy)
                    ?? throw new InvalidOperationException("Overridden federation handlers require AAuthFederationOptions.TransportContract.");
                contract = AAuthTransportContract.EnforcesEgressPolicy;
            }
            var signed = sp.GetRequiredKeyedService<IAAuthServerIdentity>(key).CreateSignedClient(transport, contract);
            return new AccessServerClient(signed, metadata, new AuthTokenResponseValidator(metadata, sp.GetRequiredService<JwksClient>()));
        }));
        return this;
    }

    /// <summary>
    /// Enable the mission governance seams (§PS Governance Endpoints): the policy and user-channel
    /// defaults from <c>AddAAuthGovernance</c>. Advertise the endpoints with the
    /// <see cref="AAuthPersonServerOptions"/> <c>MissionPath</c>, <c>PermissionPath</c>,
    /// <c>AuditPath</c> and <c>InteractionEndpointPath</c>.
    /// </summary>
    public AAuthPersonServerBuilder WithGovernance()
    {
        Services.AddAAuthGovernance();
        return this;
    }

    private AAuthPersonServerBuilder Use<TService, TImplementation>()
        where TService : class where TImplementation : class, TService
    {
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton<TService, TImplementation>(Name));
        return this;
    }

    private AAuthPersonServerBuilder Use<TService>(TService instance) where TService : class
    {
        ArgumentNullException.ThrowIfNull(instance);
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton(Name, instance));
        return this;
    }

    private AAuthPersonServerBuilder Use<TService>(Func<IServiceProvider, TService> factory) where TService : class
    {
        ArgumentNullException.ThrowIfNull(factory);
        AAuthServerRoles.ReplaceKeyed(Services, ServiceDescriptor.KeyedSingleton<TService>(Name, (sp, _) => factory(sp)));
        return this;
    }
}

/// <summary>Registers AAuth Person Server instances.</summary>
public static class AAuthPersonServerServiceCollectionExtensions
{
    /// <summary>The configuration section a Person Server binds from by default.</summary>
    public const string ConfigurationSection = "AAuth:PersonServer";

    /// <summary>
    /// Register a Person Server instance. Map it with <c>app.MapAAuthPersonServer(name)</c>.
    /// Validated at startup: a missing issuer or signing key fails fast.
    /// </summary>
    public static AAuthPersonServerBuilder AddAAuthPersonServer(this IServiceCollection services, string? name = null,
        Action<AAuthPersonServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        name ??= AAuthPersonServerBuilder.DefaultName;
        var builder = new AAuthPersonServerBuilder(services, name);
        var options = services.AddValidatedAAuthOptions<AAuthPersonServerOptions, PersonServerOptionsValidator>(name);
        if (configure is not null) options.Configure(configure);

        services.AddAAuthDiscovery();
        services.TryAddSingleton<AAuth.HttpSig.AAuthVerifier>();
        services.TryAddSingleton<IMissionStore, InMemoryMissionStore>();
        services.TryAddSingleton<IMissionLog, InMemoryMissionLog>();

        services.TryAddKeyedSingleton<IAAuthServerIdentity>(name, (sp, key) =>
        {
            var instance = (string)key!;
            var value = sp.GetRequiredService<IOptionsMonitor<AAuthPersonServerOptions>>().Get(instance);
            AAuthServerRoles.LoadKeyHandle(value.SigningKeys, value.KeyHandle, value.KeyId, sp, nameof(AAuthPersonServerOptions));
            return new AAuthServerIdentity(instance, value.Issuer, AuthTokenBuilder.PersonDwk, value.SigningKeys, value.EgressPolicy);
        });
        services.TryAddKeyedSingleton<IPersonPendingStore>(name, (sp, _) =>
            sp.GetService<IPersonPendingStore>() ?? new InMemoryPersonPendingStore());
        services.TryAddKeyedSingleton<IIdentityClaimsAsserter>(name, (sp, _) =>
            sp.GetService<IIdentityClaimsAsserter>() ?? new DefaultIdentityClaimsAsserter());
        services.TryAddKeyedSingleton<TokenVerifier>(name, (sp, key) => sp.GetService<TokenVerifier>() ?? Verifier(sp, (string)key!));
        services.TryAddKeyedSingleton<IJtiStore>(name, (sp, key) => sp.GetService<IJtiStore>()
            ?? new InMemoryJtiStore(sp.GetRequiredService<IOptionsMonitor<AAuthPersonServerOptions>>().Get((string)key!).TimeProvider));
        services.TryAddKeyedSingleton<AAuthRevocationService>(name, (sp, key) => AAuthRevocationService.ForIdentity(sp,
            sp.GetRequiredKeyedService<IAAuthServerIdentity>(key), sp.GetRequiredKeyedService<IJtiStore>(key),
            sp.GetRequiredService<IOptionsMonitor<AAuthPersonServerOptions>>().Get((string)key!).TimeProvider, key,
            sp.GetService<IMissionStore>()));
        services.TryAddKeyedSingleton<IAAuthRevocationService>(name, (sp, key) => sp.GetRequiredKeyedService<AAuthRevocationService>(key));
        return builder;

        static TokenVerifier Verifier(IServiceProvider sp, string instance)
        {
            var value = sp.GetRequiredService<IOptionsMonitor<AAuthPersonServerOptions>>().Get(instance);
            return new TokenVerifier { EgressPolicy = value.EgressPolicy, TimeProvider = value.TimeProvider };
        }
    }

    /// <summary>Register a Person Server instance bound from <paramref name="configuration"/> (for example <c>AAuth:PersonServer</c>).</summary>
    public static AAuthPersonServerBuilder AddAAuthPersonServer(this IServiceCollection services, IConfiguration configuration,
        string? name = null, Action<AAuthPersonServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var builder = services.AddAAuthPersonServer(name, configure: null);
        services.AddOptions<AAuthPersonServerOptions>(builder.Name).Bind(configuration);
        if (configure is not null) builder.Configure(configure);
        return builder;
    }
}

internal sealed class PersonServerOptionsValidator(IServiceProvider services) : AAuthOptionsValidator<AAuthPersonServerOptions>
{
    protected override void Validate(string? name, AAuthPersonServerOptions options, List<string> failures)
    {
        // The issuer is the token iss/aud anchor; the interaction path is appended with
        // `?code=…`; each trusted Access Server is a four-party anchor.
        if (!AAuthUrl.IsHttpsOrLoopback(options.Issuer, options.EgressPolicy))
            failures.Add("AAuthPersonServerOptions.Issuer must be an absolute https URL (loopback http allowed for development).");
        try { AAuthServerRoles.RejectDevelopmentLoopbackInProduction(services, $"Person Server '{name}'", options.EgressPolicy); }
        catch (InvalidOperationException exception) { failures.Add(exception.Message); }
        if (options.SigningKeys.Count == 0 && string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("AAuthPersonServerOptions needs a signing key: add one to SigningKeys or set KeyHandle.");
        AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.TokenPath, nameof(options.TokenPath), failures);
        AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.PersonTokenPath, nameof(options.PersonTokenPath), failures);
        AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.RevocationPath, nameof(options.RevocationPath), failures);
        AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.InteractionPath, nameof(options.InteractionPath), failures);
        if (options.InteractionEndpointPath is not null)
            AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.InteractionEndpointPath, nameof(options.InteractionEndpointPath), failures);
        if (options.MissionPath is not null)
            AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.MissionPath, nameof(options.MissionPath), failures);
        if (options.PermissionPath is not null)
            AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.PermissionPath, nameof(options.PermissionPath), failures);
        if (options.AuditPath is not null)
            AAuthMetadataUrl.ValidateDerivedEndpoint(options.EgressPolicy, options.Issuer, options.AuditPath, nameof(options.AuditPath), failures);
        foreach (var trustedAs in options.Trust.AccessServers.Allowed ?? new HashSet<string>())
        {
            if (!AAuthUrl.IsHttpsOrLoopback(trustedAs, options.EgressPolicy))
                failures.Add($"AAuthPersonServerOptions.Trust.AccessServers entry '{trustedAs}' must be an absolute https URL " +
                    "(loopback http allowed for development).");
        }
    }
}
