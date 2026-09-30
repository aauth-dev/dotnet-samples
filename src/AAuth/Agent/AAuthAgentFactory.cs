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

/// <summary>An AAuth agent: its signed, challenge-handling <see cref="System.Net.Http.HttpClient"/>.</summary>
public sealed class AAuthAgent : IDisposable
{
    private readonly bool _owned;

    internal AAuthAgent(string name, HttpClient httpClient, bool owned)
    {
        Name = name;
        HttpClient = httpClient;
        _owned = owned;
    }

    /// <summary>The agent name.</summary>
    public string Name { get; }

    /// <summary>The agent's <see cref="System.Net.Http.HttpClient"/>. Reuse it: it holds the agent's token caches.</summary>
    public HttpClient HttpClient { get; }

    /// <summary>Dispose a caller-owned agent. A registered agent is disposed with its container.</summary>
    public void Dispose()
    {
        if (_owned) HttpClient.Dispose();
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
            return new AAuthAgent(key, client, owned: false);
        });
    }

    public AAuthAgent Create(AAuthAgentDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var validation = new AAuthAgentOptionsValidator().Validate(descriptor.Name, descriptor);
        if (validation.Failed)
            throw new Microsoft.Extensions.Options.OptionsValidationException(descriptor.Name, typeof(AAuthAgentOptions),
                validation.Failures ?? []);
        return new AAuthAgent(descriptor.Name, AAuthAgentComposer.CreateBuilder(descriptor, services, descriptor.Name).Build(), owned: true);
    }

    public AAuthAgent Create(string name, IAAuthSigner signer, Action<AAuthClientBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new AAuthClientBuilder(signer);
        configure(builder);
        return new AAuthAgent(name, builder.Build(), owned: true);
    }

    public void Dispose()
    {
        foreach (var agent in _registered.Values) agent.HttpClient.Dispose();
        _registered.Clear();
    }
}
