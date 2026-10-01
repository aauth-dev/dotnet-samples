using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;

namespace SampleApp;

/// <summary>
/// Manages one-time enrollment with the Agent Provider.
/// In production, enrollment is a separate provisioning step — only the
/// local key handle is persisted. Here we enrol on first use for demo simplicity,
/// then create one agent for the enrolled identity and keep it.
/// </summary>
public sealed class EnrollmentService : IDisposable
{
    private readonly IConfiguration _config;
    private readonly SampleAgents _agents;
    private readonly IAAuthAgentFactory _factory;
    private readonly InMemoryAAuthAccessStore _accessStore = new();
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    private IAAuthSigner? _key;
    private string? _localKeyHandle;
    private string? _agentTokenKid;
    private string? _jwksUri;
    private string? _refreshEndpoint;
    private IKeyStore? _keyStore;
    private AAuthAgent? _agent;

    public EnrollmentService(IConfiguration config, SampleAgents agents, IAAuthAgentFactory factory)
    {
        _config = config;
        _agents = agents;
        _factory = factory;
    }

    public IAAuthSigner Key => _key ?? throw new InvalidOperationException("Not enrolled yet.");
    public string LocalKeyHandle => _localKeyHandle ?? throw new InvalidOperationException("Not enrolled yet.");
    public string? AgentTokenKid => _agentTokenKid;
    public string? JwksUri => _jwksUri;
    public string RefreshEndpoint => _refreshEndpoint ?? throw new InvalidOperationException("Not enrolled yet.");
    public IKeyStore KeyStore => _keyStore ?? throw new InvalidOperationException("Not enrolled yet.");
    public bool IsEnrolled => _key is not null;

    /// <summary>
    /// The agent for the enrolled identity: agent token refreshed at the AP with the durable key,
    /// resource-managed access, and resource interaction handling. Owned by this service.
    /// </summary>
    public AAuthAgent Agent => _agent ?? throw new InvalidOperationException("Not enrolled yet.");

    /// <summary>
    /// Demo only: forget the <c>AAuth-Access</c> token held for <paramref name="resource"/> so the
    /// next request asks for consent again.
    /// </summary>
    public void StartOver(string resource)
        => _accessStore.Remove(new Uri(resource).GetLeftPart(UriPartial.Authority),
            signingKeyThumbprint: Key.ComputeJwkThumbprint());

    public void Dispose() => _agent?.Dispose();

    public async Task EnsureEnrolledAsync()
    {
        if (_key is not null) return;

        await _semaphore.WaitAsync();
        try
        {
            if (_key is not null) return;

            var apBase = _config["AAuth:AgentProvider"]!;
            var agentId = _config["AAuth:AgentId"]!;
            var personServer = _agents.PersonServer;

            // Use a file-based key store so the key survives app restarts
            var keyStore = AAuth.Crypto.FileKeyStore.Default();
            _keyStore = keyStore;

            // Discover AP metadata
            using var http = new SampleHttpClient();
            using var metadataClient = new MetadataClient(http);
            var metaUrl = MetadataClient.BuildUrl(apBase, "aauth-agent.json", SampleEgress.Policy);
            var apMeta = await metadataClient.FetchAsync(metaUrl);
            var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apBase}/enrol";
            _refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apBase}/refresh";

            // Enrol with the AP (key generated inside the store)
            var durableKey = keyStore.LoadOrCreate("sample-app");
            var enrollment = AAuth.AAuthClientBuilder.Bootstrap(enrolEndpoint)
                .WithEgressPolicy(SampleEgress.Policy)
                .WithKey(durableKey)
                .WithKeyStore(keyStore);
            if (!string.IsNullOrEmpty(personServer)) enrollment.WithPersonServer(personServer);
            var result = await enrollment.EnrolAsync();

            // Deliberately discard result.AgentToken — we only keep the local key handle.
            // At runtime the SDK acquires a fresh token via the refresh endpoint
            // (signed with the durable key). This simulates out-of-band enrollment
            // where the app never sees the initial token.
            // One agent per enrollment, reused by every Inbox request.
            _agent = _factory.Create(new AAuthAgentDescriptor("sample-app-enrolled")
            {
                EgressPolicy = SampleEgress.Policy,
                KeyHandle = result.LocalKeyHandle,
                AgentProvider = { RefreshEndpoint = _refreshEndpoint },
                EnableResourceManagedAccess = true,
                AAuthAccessStore = _accessStore,
                HandleInteractions = true,
                Interaction = { DefaultPollInterval = TimeSpan.FromSeconds(1) },
            });
            _key = result.Key;
            _localKeyHandle = result.LocalKeyHandle;
            _agentTokenKid = result.AgentTokenKid;
            _jwksUri = result.JwksUri;
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
