using System;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth;

/// <summary>
/// Fluent builder for the bootstrap enrollment flow. Created via
/// <see cref="AAuthClientBuilder.Bootstrap(string, string)"/>.
/// Enrollment is a one-time operation that produces an <see cref="EnrollResult"/>.
/// Use the result with <see cref="AAuthClientBuilder"/> to build clients separately.
/// </summary>
public sealed class BootstrapBuilder
{
    private readonly string _enrollEndpoint;
    private readonly string? _agentId;
    private AAuthKey? _key;
    private string? _personServer;
    private IKeyStore? _keyStore;
    private IPlatformAttestor? _attestor;
    private Discovery.AAuthEgressPolicy _egressPolicy = Discovery.AAuthEgressPolicy.Production;

    /// <summary>Set the network admission policy for enrollment.</summary>
    public BootstrapBuilder WithEgressPolicy(Discovery.AAuthEgressPolicy policy)
    {
        _egressPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
        return this;
    }

    /// <summary>Admit only the specified development loopback origins.</summary>
    public BootstrapBuilder WithDevelopmentLoopback(params string[] origins) =>
        WithEgressPolicy(Discovery.AAuthEgressPolicy.ForDevelopmentLoopback(origins));

    internal BootstrapBuilder(string enrollEndpoint, string? agentId)
    {
        _enrollEndpoint = enrollEndpoint;
        _agentId = agentId;
    }

    /// <summary>Reuse a durable key for authenticated, idempotent enrollment.</summary>
    public BootstrapBuilder WithKey(AAuthKey key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        return this;
    }

    /// <summary>Set the Person Server URL to associate with this agent during enrollment.</summary>
    public BootstrapBuilder WithPersonServer(string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _personServer = personServer;
        return this;
    }

    /// <summary>Override the key store (defaults to in-memory).</summary>
    public BootstrapBuilder WithKeyStore(IKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        _keyStore = keyStore;
        return this;
    }

    /// <summary>Set a platform attestor for enrollment.</summary>
    public BootstrapBuilder WithAttestor(IPlatformAttestor attestor)
    {
        ArgumentNullException.ThrowIfNull(attestor);
        _attestor = attestor;
        return this;
    }

    /// <summary>
    /// Enrol with the Agent Provider and return the enrollment result.
    /// </summary>
    /// <returns>The enrollment result containing the agent token, key, and key ID.</returns>
    public async System.Threading.Tasks.Task<EnrollResult> EnrolAsync(
        System.Threading.CancellationToken cancellationToken = default)
    {
        var keyStore = _keyStore ?? new InMemoryKeyStore();
        using var http = Discovery.AAuthHttpTransport.CreateClient(_egressPolicy);
        var apClient = new AgentProviderClient(http, keyStore, _attestor);

        // Extract AP issuer from the enrollment endpoint (base URL)
        var enrollUri = new Uri(_enrollEndpoint);
        var apIssuer = $"{enrollUri.Scheme}://{enrollUri.Authority}";

        return await apClient.EnrolWithKeyAsync(
            apIssuer, _agentId, _enrollEndpoint, _key ?? AAuthKey.Generate(), _personServer, cancellationToken);
    }
}
