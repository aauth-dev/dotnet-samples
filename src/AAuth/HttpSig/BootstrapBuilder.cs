using System;
using AAuth.Agent;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Fluent builder for the bootstrap enrollment flow. Created via
/// <see cref="AAuthClientBuilder.Bootstrap(string, string)"/>.
/// Enrollment is a one-time operation that produces an <see cref="EnrollResult"/>.
/// Use the result with <see cref="AAuthClientBuilder"/> to build clients separately.
/// </summary>
public sealed class BootstrapBuilder
{
    private readonly string _enrollEndpoint;
    private readonly string _agentId;
    private string? _personServer;
    private IKeyStore? _keyStore;
    private IPlatformAttestor? _attestor;

    internal BootstrapBuilder(string enrollEndpoint, string agentId)
    {
        _enrollEndpoint = enrollEndpoint;
        _agentId = agentId;
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
        var apClient = new AgentProviderClient(new System.Net.Http.HttpClient(), keyStore, _attestor);

        // Extract AP issuer from the enrollment endpoint (base URL)
        var enrollUri = new Uri(_enrollEndpoint);
        var apIssuer = $"{enrollUri.Scheme}://{enrollUri.Authority}";

        return await apClient.EnrolAsync(
            apIssuer, _agentId, _enrollEndpoint, _personServer, cancellationToken);
    }
}
