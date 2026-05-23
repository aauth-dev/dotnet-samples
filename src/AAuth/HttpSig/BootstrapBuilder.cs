using System;
using AAuth.Agent;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Options for the bootstrap enrollment shorthand.
/// </summary>
public sealed class BootstrapOptions
{
    /// <summary>
    /// Key store for persisting the generated key. Defaults to <see cref="InMemoryKeyStore"/>.
    /// </summary>
    public IKeyStore? KeyStore { get; set; }

    /// <summary>
    /// Platform attestor for AP enrollment. Defaults to no-op.
    /// </summary>
    public IPlatformAttestor? Attestor { get; set; }

    /// <summary>
    /// Person Server URL to associate with this agent. Optional.
    /// </summary>
    public string? PersonServer { get; set; }
}

/// <summary>
/// Fluent builder for the bootstrap enrollment flow. Created via
/// <see cref="AAuthClientBuilder.Bootstrap(string, string)"/>.
/// </summary>
public sealed class BootstrapBuilder
{
    private readonly string _enrollEndpoint;
    private readonly string _agentId;
    private string? _personServer;
    private IKeyStore? _keyStore;
    private IPlatformAttestor? _attestor;

    // Post-enrollment builder configuration
    private bool _challengeHandling;
    private Action<ChallengeHandlingOptions>? _challengeOptionsConfigure;
    private bool _interactionHandling;
    private Action<InteractionHandlingOptions>? _interactionOptionsConfigure;

    internal BootstrapBuilder(string enrollEndpoint, string agentId)
    {
        _enrollEndpoint = enrollEndpoint;
        _agentId = agentId;
    }

    /// <summary>Set the Person Server URL for enrollment and post-enrollment challenge handling.</summary>
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

    /// <summary>Enable challenge handling on the resulting client.</summary>
    public BootstrapBuilder WithChallengeHandling()
    {
        _challengeHandling = true;
        return this;
    }

    /// <summary>Enable challenge handling with options on the resulting client.</summary>
    public BootstrapBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _challengeHandling = true;
        _challengeOptionsConfigure = configure;
        return this;
    }

    /// <summary>Enable interaction handling on the resulting client.</summary>
    public BootstrapBuilder WithInteractionHandling(Action<InteractionHandlingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _interactionHandling = true;
        _interactionOptionsConfigure = configure;
        return this;
    }

    /// <summary>
    /// Enrol with the AP and build a ready-to-use <see cref="System.Net.Http.HttpClient"/>.
    /// </summary>
    /// <returns>Tuple of the built client and the enrollment result.</returns>
    public async System.Threading.Tasks.Task<(System.Net.Http.HttpClient Client, EnrollResult Enrollment)> EnrolAndBuildAsync(
        System.Threading.CancellationToken cancellationToken = default)
    {
        var keyStore = _keyStore ?? new InMemoryKeyStore();
        var apClient = new AgentProviderClient(new System.Net.Http.HttpClient(), keyStore, _attestor);

        // Extract AP issuer from the enrollment endpoint (base URL)
        var enrollUri = new Uri(_enrollEndpoint);
        var apIssuer = $"{enrollUri.Scheme}://{enrollUri.Authority}";

        var result = await apClient.EnrolAsync(
            apIssuer, _agentId, _enrollEndpoint, _personServer, cancellationToken);

        // Build a client using the enrollment result
        var builder = new AAuthClientBuilder(result.Key)
            .UseJwt(result.AgentToken);

        if (_challengeHandling)
        {
            if (_personServer is not null)
            {
                if (_challengeOptionsConfigure is not null)
                    builder.WithChallengeHandling(_personServer, _challengeOptionsConfigure);
                else
                    builder.WithChallengeHandling(_personServer);
            }
            else
            {
                if (_challengeOptionsConfigure is not null)
                    builder.WithChallengeHandling(_challengeOptionsConfigure);
                else
                    builder.WithChallengeHandling();
            }
        }

        if (_interactionHandling && _interactionOptionsConfigure is not null)
        {
            builder.WithInteractionHandling(_interactionOptionsConfigure);
        }

        return (builder.Build(), result);
    }
}
