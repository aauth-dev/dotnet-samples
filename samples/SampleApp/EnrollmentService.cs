using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;

namespace SampleApp;

/// <summary>
/// Manages one-time enrollment with the Agent Provider.
/// In production, enrollment is a separate provisioning step — only the
/// key ID is persisted. Here we enrol on first use for demo simplicity.
/// </summary>
public sealed class EnrollmentService
{
    private readonly IConfiguration _config;
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    private IAAuthKey? _key;
    private string? _keyId;
    private string? _jwksUri;
    private string? _refreshEndpoint;
    private IKeyStore? _keyStore;

    public EnrollmentService(IConfiguration config)
    {
        _config = config;
    }

    public IAAuthKey Key => _key ?? throw new InvalidOperationException("Not enrolled yet.");
    public string KeyId => _keyId ?? throw new InvalidOperationException("Not enrolled yet.");
    public string? JwksUri => _jwksUri;
    public string RefreshEndpoint => _refreshEndpoint ?? throw new InvalidOperationException("Not enrolled yet.");
    public IKeyStore KeyStore => _keyStore ?? throw new InvalidOperationException("Not enrolled yet.");
    public bool IsEnrolled => _key is not null;

    public async Task EnsureEnrolledAsync()
    {
        if (_key is not null) return;

        await _semaphore.WaitAsync();
        try
        {
            if (_key is not null) return;

            var apBase = _config["AAuth:AgentProvider"]!;
            var agentId = _config["AAuth:AgentId"]!;
            var personServer = _config["AAuth:PersonServer"];

            // Use a file-based key store so the key survives app restarts
            var keyStore = AAuth.Crypto.KeyStore.Default();
            _keyStore = keyStore;

            // Discover AP metadata
            var metadataClient = new MetadataClient(new HttpClient());
            var metaUrl = MetadataClient.BuildUrl(apBase, "aauth-agent.json");
            var apMeta = await metadataClient.FetchAsync(metaUrl);
            var enrolEndpoint = (string?)apMeta["enrol_endpoint"] ?? $"{apBase}/enrol";
            _refreshEndpoint = (string?)apMeta["refresh_endpoint"] ?? $"{apBase}/refresh";

            // Enrol with the AP (key generated inside the store)
            var apClient = new AgentProviderClient(new HttpClient(), keyStore);
            var result = await apClient.EnrolAsync(apBase, agentId, enrolEndpoint, personServer);

            _key = result.Key;
            _keyId = result.KeyId;
            _jwksUri = result.JwksUri;
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
