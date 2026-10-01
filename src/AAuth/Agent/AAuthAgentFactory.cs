using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using AAuth.Crypto;
using AAuth.Discovery;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Agent;

/// <summary>
/// Resolves registered agents and creates agents unknown at startup: per tenant, per user,
/// or a per-request intermediary. Registered agents are owned by the factory; the caller
/// owns and disposes the agents it creates.
/// </summary>
public interface IAAuthAgentFactory
{
    /// <summary>The agent registered with <c>AddAAuthAgent(name)</c>. Factory-owned: disposing it does nothing.</summary>
    AAuthAgent Get(string name);

    /// <summary>Create an agent from options, validated as a registered agent's are. Caller-owned.</summary>
    AAuthAgent Create(AAuthAgentDescriptor descriptor);

    /// <summary>Create an agent from the primitive builder. Caller-owned.</summary>
    AAuthAgent Create(string name, IAAuthSigner signer, Action<AAuthClientBuilder> configure);
}

/// <summary>The options of an agent created at runtime through <see cref="IAAuthAgentFactory.Create(AAuthAgentDescriptor)"/>.</summary>
public sealed class AAuthAgentDescriptor : AAuthAgentOptions
{
    /// <summary>Describe an agent named <paramref name="name"/>, for example a tenant identifier.</summary>
    public AAuthAgentDescriptor(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        Name = name;
    }

    /// <summary>The agent name.</summary>
    public string Name { get; }
}

/// <summary>
/// An AAuth agent: its signed, challenge-handling <see cref="System.Net.Http.HttpClient"/> and the typed
/// clients for its Person Server, all signed as this agent.
/// </summary>
public sealed class AAuthAgent : IDisposable
{
    private readonly bool _owned;
    private readonly Func<Type, object> _clients;
    private readonly Lazy<AAuthAgentChannel>? _channel;

    internal AAuthAgent(string name, HttpClient httpClient, bool owned, Func<Type, object> clients,
        Lazy<AAuthAgentChannel>? channel = null)
    {
        Name = name;
        HttpClient = httpClient;
        _owned = owned;
        _clients = clients;
        _channel = channel;
    }

    /// <summary>The agent name.</summary>
    public string Name { get; }

    /// <summary>The agent's <see cref="System.Net.Http.HttpClient"/>. Reuse it: it holds the agent's token caches.</summary>
    public HttpClient HttpClient { get; }

    /// <summary>Person token requests and token exchanges at the Person Server.</summary>
    public TokenExchangeClient TokenExchange => (TokenExchangeClient)_clients(typeof(TokenExchangeClient));

    /// <summary>Mission, permission, audit and interaction calls at the agent's Person Server.</summary>
    public Governance.AAuthGovernanceClient Governance
        => (Governance.AAuthGovernanceClient)_clients(typeof(Governance.AAuthGovernanceClient));

    /// <summary>Server-signed revocation requests, signed as this agent.</summary>
    public AAuth.Server.RevocationClient Revocation => (AAuth.Server.RevocationClient)_clients(typeof(AAuth.Server.RevocationClient));

    /// <summary>Dispose a caller-owned agent. A registered agent is disposed with its container.</summary>
    public void Dispose()
    {
        if (!_owned) return;
        HttpClient.Dispose();
        if (_channel is { IsValueCreated: true }) _channel.Value.Dispose();
    }
}

internal sealed class AAuthAgentFactory(IServiceProvider services) : IAAuthAgentFactory, IDisposable
{
    private readonly ConcurrentDictionary<string, AAuthAgent> _registered = new(StringComparer.Ordinal);

    public AAuthAgent Get(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (!services.GetServices<AAuthAgentRegistration>().Any(registration => registration.Name == name))
            throw new InvalidOperationException($"No agent named '{name}' is registered; call AddAAuthAgent(\"{name}\").");
        return _registered.GetOrAdd(name, key =>
        {
            var options = AAuthAgentComposer.Options(services, key);
            var client = services.GetRequiredService<IHttpClientFactory>().CreateClient(key);
            AAuthHttpTransport.AttachPolicy(client, AAuthAgentComposer.Egress(options),
                options.TransportContract ?? AAuthTransportContract.EnforcesEgressPolicy);
            return new AAuthAgent(key, client, owned: false, type => services.GetRequiredKeyedService(type, key));
        });
    }

    public AAuthAgent Create(AAuthAgentDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var validation = new AAuthAgentOptionsValidator(services).Validate(descriptor.Name, descriptor);
        if (validation.Failed)
            throw new Microsoft.Extensions.Options.OptionsValidationException(descriptor.Name, typeof(AAuthAgentOptions),
                validation.Failures ?? []);
        var channel = new Lazy<AAuthAgentChannel>(() => AAuthAgentChannel.Create(descriptor, services, descriptor.Name));
        return new AAuthAgent(descriptor.Name, AAuthAgentComposer.CreateBuilder(descriptor, services, descriptor.Name).Build(),
            owned: true, type => channel.Value.Client(type), channel);
    }

    public AAuthAgent Create(string name, IAAuthSigner signer, Action<AAuthClientBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new AAuthClientBuilder(signer);
        configure(builder);
        var channel = new Lazy<AAuthAgentChannel>(() => new AAuthAgentChannel(builder, services, personServer: builder.PersonServer));
        return new AAuthAgent(name, builder.Build(), owned: true, type => channel.Value.Client(type), channel);
    }

    public void Dispose()
    {
        foreach (var agent in _registered.Values) agent.HttpClient.Dispose();
        _registered.Clear();
    }
}

/// <summary>
/// An agent's Person Server channel: a client signed as the agent (never a carrier) and the typed
/// clients over it, sharing one metadata client.
/// </summary>
internal sealed class AAuthAgentChannel : IDisposable
{
    private readonly bool _ownsMetadata;
    private readonly string? _personServer;
    private readonly Lazy<TokenExchangeClient> _tokenExchange;
    private readonly Lazy<Governance.AAuthGovernanceClient> _governance;
    private readonly Lazy<AAuth.Server.RevocationClient> _revocation;

    internal AAuthAgentChannel(AAuthClientBuilder builder, IServiceProvider services, string? personServer,
        Governance.GovernanceOptions? governanceDefaults = null)
    {
        Signed = builder.BuildAgentSigned();
        var shared = services.GetService<MetadataClient>();
        _ownsMetadata = shared is null;
        Metadata = shared ?? new MetadataClient(policy: builder.EgressPolicy);
        _personServer = personServer;
        _tokenExchange = new(() => new TokenExchangeClient(Signed, Metadata));
        _governance = new(() => new Governance.AAuthGovernanceClient(Signed, Metadata, PersonServer, governanceDefaults));
        _revocation = new(() => new AAuth.Server.RevocationClient(Signed));
    }

    public static AAuthAgentChannel Create(AAuthAgentOptions options, IServiceProvider services, string name,
        Governance.GovernanceOptions? governanceDefaults = null)
    {
        var builder = AAuthAgentComposer.CreateBuilder(options, services, name);
        return new(builder, services, builder.PersonServer,
            governanceDefaults ?? GovernanceDefaults(options, services, name));
    }

    // Governance calls wait on the same Person Server as challenge handling, so they share its
    // callbacks (options delegate, then the handler keyed by agent name, then unkeyed) and budget.
    private static Governance.GovernanceOptions GovernanceDefaults(AAuthAgentOptions options, IServiceProvider services,
        string name)
    {
        var challenge = options.Challenge;
        var interaction = AAuthAgentComposer.Handler<IAAuthInteractionHandler>(services, name);
        var clarification = AAuthAgentComposer.Handler<IAAuthClarificationHandler>(services, name);
        return new()
        {
            OnInteractionRequired = challenge.OnInteractionRequired
                ?? (interaction is null ? null : interaction.OnInteractionRequiredAsync),
            OnClarificationRequired = challenge.OnClarificationRequired
                ?? (clarification is null ? null : clarification.OnClarificationRequiredAsync),
            MaxClarificationRounds = challenge.MaxClarificationRounds,
            PollerOptions = new DeferredPollerOptions
            {
                MaxTotalWait = challenge.PollingTimeout,
                DefaultPollInterval = challenge.DefaultPollInterval,
                PreferWaitSeconds = challenge.PreferWaitSeconds,
                MinPollInterval = challenge.MinPollInterval,
                OnPoll = challenge.OnPoll,
            },
        };
    }

    public HttpClient Signed { get; }
    public MetadataClient Metadata { get; }

    public string PersonServer => _personServer
        ?? throw new InvalidOperationException("The agent's Person Server clients require AAuthAgentOptions.PersonServer.");

    public TokenExchangeClient TokenExchange => _tokenExchange.Value;
    public Governance.AAuthGovernanceClient Governance => _governance.Value;
    public AAuth.Server.RevocationClient Revocation => _revocation.Value;

    public object Client(Type type)
        => type == typeof(TokenExchangeClient) ? TokenExchange
            : type == typeof(Governance.AAuthGovernanceClient) ? Governance
            : type == typeof(AAuth.Server.RevocationClient) ? Revocation
            : throw new ArgumentOutOfRangeException(nameof(type));

    public void Dispose()
    {
        if (_governance.IsValueCreated) _governance.Value.Dispose();
        Signed.Dispose();
        if (_ownsMetadata) Metadata.Dispose();
    }
}
