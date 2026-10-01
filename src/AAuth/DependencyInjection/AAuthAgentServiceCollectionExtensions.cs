using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using AAuth;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server.CallChaining;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering named AAuth agents via DI.
/// </summary>
public static class AAuthAgentServiceCollectionExtensions
{
    /// <summary>The configuration section agents bind from by default: <c>AAuth:Agents:&lt;name&gt;</c>.</summary>
    public const string ConfigurationSection = "AAuth:Agents";

    /// <summary>
    /// Register a named AAuth agent: a <see cref="System.Net.Http.HttpClient"/> resolved through
    /// <see cref="IHttpClientFactory.CreateClient(string)"/> or <see cref="IAAuthAgentFactory.Get(string)"/>.
    /// Options are validated when the host starts: exactly one identity source, one key.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The logical name for the HttpClient (used with IHttpClientFactory).</param>
    /// <param name="configure">Configure the agent options.</param>
    public static AAuthAgentBuilder AddAAuthAgent(this IServiceCollection services, string name,
        Action<AAuthAgentOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);

        services.AddValidatedAAuthOptions<AAuthAgentOptions, AAuthAgentOptionsValidator>(name);
        if (configure is not null) services.Configure(name, configure);
        services.AddAAuthAgentFactory();
        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddSingleton(new AAuthAgentRegistration(name));
        services.TryAddKeyedSingleton<IAAuthTokenCache>(name, (_, _) => new InMemoryAAuthTokenCache());
        AddTypedClients(services, name);

        // Composed from the service provider at first resolve; the pipeline (and its token
        // caches) lives as long as the container. Deferred polling is bounded by the handlers'
        // PollingTimeout and each HTTP call by the egress policy, not by HttpClient.Timeout.
        var httpClient = services.AddHttpClient(name)
            .ConfigurePrimaryHttpMessageHandler(sp => AAuthAgentComposer.CreateBuilder(AAuthAgentComposer.Options(sp, name), sp, name)
                .BuildHandler())
            .ConfigureHttpClient(client => client.Timeout = Timeout.InfiniteTimeSpan)
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
        return new AAuthAgentBuilder(services, name, httpClient);
    }

    // Typed clients keyed by agent name, signed as the agent (never as a carrier) and sharing
    // one channel and metadata client.
    private static void AddTypedClients(IServiceCollection services, string name)
    {
        services.TryAddKeyedSingleton(name, (sp, key) => AAuthAgentChannel.Create(
            AAuthAgentComposer.Options(sp, (string)key!), sp, (string)key!,
            sp.GetKeyedService<AAuthGovernanceDefaults>(key)?.Options));
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthAgentChannel>(key).TokenExchange);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthAgentChannel>(key).Governance);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthAgentChannel>(key).Revocation);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthGovernanceClient>(key).Mission);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthGovernanceClient>(key).Permission);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthGovernanceClient>(key).Audit);
        services.TryAddKeyedSingleton(name, (sp, key) => sp.GetRequiredKeyedService<AAuthGovernanceClient>(key).Interaction);
    }

    /// <summary>
    /// Register a named agent bound from <paramref name="configuration"/> (for example
    /// <c>AAuth:Agents:&lt;name&gt;</c>), then <paramref name="configure"/>.
    /// </summary>
    public static AAuthAgentBuilder AddAAuthAgent(this IServiceCollection services, string name,
        IConfiguration configuration, Action<AAuthAgentOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var builder = services.AddAAuthAgent(name);
        services.AddOptions<AAuthAgentOptions>(name).Bind(configuration);
        if (configure is not null) builder.Configure(configure);
        return builder;
    }

    /// <summary>
    /// Register <see cref="IAAuthAgentFactory"/> for agents created at runtime (per tenant, per
    /// user, per request). <c>AddAAuthAgent</c> registers it too.
    /// </summary>
    public static IServiceCollection AddAAuthAgentFactory(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddHttpClient();
        services.TryAddSingleton<IAAuthAgentFactory, AAuthAgentFactory>();
        return services;
    }
}

/// <summary>
/// Configures a named agent registered with <c>AddAAuthAgent(name)</c>. The agent's pipeline is
/// composed from <see cref="AAuthClientBuilder"/>, which remains the primitive.
/// </summary>
public sealed class AAuthAgentBuilder
{
    internal AAuthAgentBuilder(IServiceCollection services, string name, IHttpClientBuilder httpClientBuilder)
    {
        Services = services;
        Name = name;
        HttpClientBuilder = httpClientBuilder;
    }

    /// <summary>The service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>The agent name; its <see cref="System.Net.Http.HttpClient"/> and services are keyed by it.</summary>
    public string Name { get; }

    /// <summary>The underlying named <see cref="System.Net.Http.HttpClient"/> registration.</summary>
    public IHttpClientBuilder HttpClientBuilder { get; }

    /// <summary>Configure the agent options.</summary>
    public AAuthAgentBuilder Configure(Action<AAuthAgentOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(Name, configure);
        return this;
    }

    /// <summary>
    /// Identify the agent through its agent provider: the agent token is refreshed at
    /// <see cref="AAuthAgentProviderOptions.RefreshEndpoint"/> with the key at
    /// <see cref="AAuthAgentOptions.KeyHandle"/>. Also registers an <see cref="AgentProviderClient"/>
    /// keyed by <see cref="Name"/> for enrolment and two-key refresh.
    /// </summary>
    public AAuthAgentBuilder WithAgentProvider(Action<AAuthAgentProviderOptions>? configure = null)
    {
        if (configure is not null) Configure(options => configure(options.AgentProvider));
        Services.TryAddKeyedSingleton(Name, (sp, key) =>
        {
            var options = AAuthAgentComposer.Options(sp, (string)key!);
            return new AgentProviderClient(AAuthHttpTransport.CreateClient(AAuthAgentComposer.Egress(options)),
                AAuthAgentComposer.KeyStore(sp), sp.GetService<IPlatformAttestor>());
        });
        return this;
    }

    /// <summary>
    /// Set the default governance options of the <see cref="AAuthGovernanceClient"/> keyed by
    /// <see cref="Name"/>. Every agent registers its typed Person Server clients
    /// (<see cref="TokenExchangeClient"/>, <see cref="AAuthGovernanceClient"/>, <see cref="MissionClient"/>,
    /// <see cref="PermissionClient"/>, <see cref="AuditClient"/>, <see cref="InteractionClient"/> and
    /// <see cref="AAuth.Server.RevocationClient"/>) keyed by its name, signed as the agent.
    /// </summary>
    public AAuthAgentBuilder WithGovernance(GovernanceOptions? defaultOptions = null)
    {
        Services.RemoveAllKeyed<AAuthGovernanceDefaults>(Name);
        Services.AddKeyedSingleton(Name, new AAuthGovernanceDefaults(defaultOptions));
        return this;
    }
}

internal sealed record AAuthGovernanceDefaults(GovernanceOptions? Options);

internal sealed record AAuthAgentRegistration(string Name);

internal sealed class AAuthAgentOptionsValidator(IServiceProvider services) : AAuthOptionsValidator<AAuthAgentOptions>
{
    protected override void Validate(string? name, AAuthAgentOptions options, List<string> failures)
    {
        if (options.Signer is null && string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("Set Signer or KeyHandle.");
        if (options.Signer is not null && !string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("Set only one of Signer and KeyHandle.");
        if (options.AgentToken is not null && options.AgentTokenFactory is not null)
            failures.Add("Set only one of AgentToken and AgentTokenFactory.");
        if (options.AgentToken is { } token && string.IsNullOrWhiteSpace(token))
            failures.Add("AgentToken is empty.");

        var tokenSource = options.AgentToken is not null || options.AgentTokenFactory is not null || options.TokenRefresher is not null;
        var selfIssued = options.SelfIssued.Issuer is not null || options.SelfIssued.Subject is not null;
        var agentProvider = options.AgentProvider.RefreshEndpoint is not null;
        var jwksUri = options.JwksUri.Id is not null || options.JwksUri.Dwk is not null || options.JwksUri.KeyId is not null;
        var sources = new List<string>();
        if (tokenSource) sources.Add("AgentToken/TokenRefresher");
        if (selfIssued) sources.Add("SelfIssued");
        if (agentProvider) sources.Add("AgentProvider");
        if (jwksUri) sources.Add("JwksUri");
        if (options.SignatureKeyProvider is not null) sources.Add("SignatureKeyProvider");
        if (sources.Count == 0)
            failures.Add("Configure an identity source: AgentToken or TokenRefresher, SelfIssued, AgentProvider, JwksUri, or SignatureKeyProvider.");
        else if (sources.Count > 1)
            failures.Add("Conflicting identity sources: " + string.Join(", ", sources) + ".");

        if (selfIssued && (string.IsNullOrEmpty(options.SelfIssued.Issuer) || string.IsNullOrEmpty(options.SelfIssued.Subject)))
            failures.Add("SelfIssued requires Issuer and Subject.");
        if (jwksUri && (string.IsNullOrEmpty(options.JwksUri.Id) || string.IsNullOrEmpty(options.JwksUri.Dwk) || string.IsNullOrEmpty(options.JwksUri.KeyId)))
            failures.Add("JwksUri requires Id, Dwk and KeyId.");
        if (agentProvider && string.IsNullOrEmpty(options.KeyHandle))
            failures.Add("AgentProvider requires KeyHandle.");

        var agentIdentity = tokenSource || selfIssued || agentProvider;
        if (!agentIdentity && (options.PersonServer is not null || options.HandleChallenges == true || options.Mission is not null
            || options.UpstreamTokenProvider is not null || options.ChainFromHttpContext))
            failures.Add("Person Server, challenge handling, missions and call chaining require an agent-token identity.");
        if (options.SignatureKeyProvider is not null && options.EnableResourceManagedAccess)
            failures.Add("A generic SignatureKeyProvider cannot be combined with resource-managed access.");
        if (options.UpstreamTokenProvider is not null && options.ChainFromHttpContext)
            failures.Add("Set only one of UpstreamTokenProvider and ChainFromHttpContext.");
        if (options.EgressPolicy is not null && options.DevelopmentLoopbackOrigins is { Length: > 0 })
            failures.Add("Set only one of EgressPolicy and DevelopmentLoopbackOrigins.");
        try
        {
            AAuth.Server.AAuthServerRoles.RejectDevelopmentLoopbackInProduction(
                services, $"Agent '{name}'", AAuthAgentComposer.Egress(options));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            failures.Add(exception.Message);
        }
    }
}

/// <summary>Composes an <see cref="AAuthClientBuilder"/> from <see cref="AAuthAgentOptions"/>.</summary>
internal static class AAuthAgentComposer
{
    public static AAuthAgentOptions Options(IServiceProvider services, string name)
        => services.GetRequiredService<IOptionsMonitor<AAuthAgentOptions>>().Get(name);

    public static AAuthEgressPolicy Egress(AAuthAgentOptions options)
        => options.EgressPolicy ?? (options.DevelopmentLoopbackOrigins is { Length: > 0 } origins
            ? AAuthEgressPolicy.ForDevelopmentLoopback(origins) : AAuthEgressPolicy.Production);

    public static IKeyStore KeyStore(IServiceProvider services) => services.GetService<IKeyStore>() ?? FileKeyStore.Default();

    public static AAuthClientBuilder CreateBuilder(AAuthAgentOptions options, IServiceProvider services, string name)
    {
        var egress = Egress(options);
        if (services.GetService<ILoggerFactory>() is { } loggerFactory)
        {
            AAuth.Server.AAuthServerRoles.WarnOnDevelopmentLoopback(
                services, loggerFactory.CreateLogger("AAuth.Agent"), "Agent", name, egress);
        }
        // R0: a delegate on the options, then a handler keyed by agent name, then an unkeyed one.
        var interactionHandler = Handler<IAAuthInteractionHandler>(services, name);
        var clarificationHandler = Handler<IAAuthClarificationHandler>(services, name);
        var observer = Handler<IAAuthDeferredObserver>(services, name);
        var signer = options.Signer ?? LoadSigner(services, options.KeyHandle!);
        AAuthClientBuilder builder;
        if (options.SelfIssued.Issuer is { } issuer)
        {
            var selfIssued = AAuthClientBuilder.SelfIssuing(signer).As(issuer, options.SelfIssued.Subject!);
            if (options.SelfIssued.KeyId is { } kid) selfIssued.WithKid(kid);
            builder = selfIssued.WithEgressPolicy(egress).ToBuilder();
        }
        else if (options.AgentProvider.RefreshEndpoint is { } refreshEndpoint)
        {
            builder = AAuthClientBuilder.Enrolled(signer).RefreshingFrom(refreshEndpoint, options.KeyHandle!)
                .WithKeyStore(KeyStore(services)).WithEgressPolicy(egress).ToBuilder();
        }
        else
        {
            builder = new AAuthClientBuilder(signer).WithEgressPolicy(egress);
        }

        if (options.AgentToken is { } agentToken) builder.UseJwt(agentToken);
        if (options.AgentTokenFactory is { } factory) builder.UseJwt(factory);
        if (options.TokenRefresher is { } refresher) builder.WithTokenRefresh(refresher, options.TokenRefreshThreshold);
        if (options.JwksUri.Id is { } id) builder.UseJwksUri(id, options.JwksUri.Dwk!, options.JwksUri.KeyId!);
        if (options.SignatureKeyProvider is { } provider) builder.UseProvider(provider);
        if (options.InnerHandler is { } inner) builder.WithInnerHandler(inner, options.TransportContract);
        if (options.Capabilities is { } capabilities) builder.WithCapabilities(capabilities);
        if (options.OnSignatureBase is { } onSignatureBase) builder.OnSignatureBase(onSignatureBase);
        if (options.PersonServer is { } personServer) builder.WithPersonServer(personServer);
        if (options.Mission is { } mission) builder.WithMission(mission);
        if (services.GetService<JwksClient>() is { } jwksClient) builder.WithTokenExchangeJwksClient(jwksClient);

        var upstream = options.UpstreamTokenProvider;
        if (options.ChainFromHttpContext)
        {
            var accessor = services.GetRequiredService<IHttpContextAccessor>();
            upstream = () => accessor.HttpContext?.Features.Get<UpstreamAuthTokenFeature>()?.Token;
        }
        if (upstream is not null) builder.WithCallChaining(upstream);

        if (options.HandleChallenges ?? (options.PersonServer is not null || upstream is not null))
            builder.WithChallengeHandling(target =>
            {
                CopyInto(options.Challenge, target);
                target.OnInteractionRequired ??= interactionHandler is null ? null : interactionHandler.OnInteractionRequiredAsync;
                target.OnClarificationRequired ??= clarificationHandler is null ? null : clarificationHandler.OnClarificationRequiredAsync;
            });
        if (options.HandleInteractions ?? (options.Interaction.OnInteractionRequired is not null
            || options.Interaction.OnApprovalPending is not null || interactionHandler is not null || observer is not null))
            builder.WithInteractionHandling(target =>
            {
                CopyInto(options.Interaction, target);
                target.OnInteractionRequired ??= interactionHandler is null ? null : interactionHandler.OnInteractionRequiredAsync;
                target.OnApprovalPending ??= observer is null ? null : observer.OnApprovalPendingAsync;
                target.OnPoll ??= observer is null ? null : observer.OnPoll;
            });
        if (options.EnableResourceManagedAccess) builder.WithResourceManagedAccess(options.AAuthAccessStore);
        builder.WithTokenCache(options.TokenCache ?? Handler<IAAuthTokenCache>(services, name) ?? new InMemoryAAuthTokenCache());
        return builder;
    }

    // Startup-only: handlers are composed synchronously by IHttpClientFactory.
    private static IAAuthSigner LoadSigner(IServiceProvider services, string keyHandle)
        => KeyStore(services).LoadAsync(keyHandle).GetAwaiter().GetResult()
            ?? throw new InvalidOperationException($"AAuthAgentOptions.KeyHandle '{keyHandle}' was not found in the key store.");

    internal static T? Handler<T>(IServiceProvider services, string name) where T : class
        => services.GetKeyedService<T>(name) ?? services.GetService<T>();

    private static void CopyInto<T>(T source, T target)
    {
        foreach (var property in typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance))
            if (property.CanRead && property.CanWrite) property.SetValue(target, property.GetValue(source));
    }
}
