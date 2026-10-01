using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Agent;

/// <summary>
/// Built-in <see cref="ITokenRefresher"/> that refreshes agent tokens via an
/// Agent Provider's refresh endpoint. Wraps <see cref="AgentProviderClient"/>.
/// </summary>
/// <remarks>
/// Use this for agents enrolled with an AP that need automatic token refresh.
/// <para>
/// The AP and the agent never share a keystore. The agent holds the durable
/// private key locally in its own <see cref="IKeyStore"/>; the AP holds only
/// the public key, indexed by JWK thumbprint. At refresh time the AP identifies
/// the enrolment from the HTTP signature — never from any string the agent sends.
/// </para>
/// </remarks>
public sealed class AgentProviderTokenRefresher : ITokenRefresher, IDisposable
{
    private readonly AgentProviderClient _client;
    private readonly string _refreshEndpoint;
    private readonly string _localKeyHandle;
    private HttpClient? _ownedHttp;
    private bool _disposed;

    /// <summary>Create a refresher that delegates to an Agent Provider.</summary>
    public AgentProviderTokenRefresher(
        HttpClient http,
        IKeyStore keyStore,
        string refreshEndpoint,
        string localKeyHandle)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);
        _client = new AgentProviderClient(http, keyStore);
        _refreshEndpoint = refreshEndpoint;
        _localKeyHandle = localKeyHandle;
    }

    /// <summary>Start building a refresher with required parameters.</summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    /// <param name="localKeyHandle">Agent-local <see cref="IKeyStore"/> handle for the durable signing key (assigned during enrollment).</param>
    public static RefresherBuilder Create(string refreshEndpoint, string localKeyHandle) => new(refreshEndpoint, localKeyHandle);

    /// <inheritdoc/>
    public async Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(context);
        return await _client.RefreshAsync(_refreshEndpoint, _localKeyHandle, cancellationToken);
    }

    /// <summary>Dispose an internally created client; injected clients remain caller-owned.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _ownedHttp?.Dispose();
    }

    /// <summary>Fluent builder for <see cref="AgentProviderTokenRefresher"/>.</summary>
    public sealed class RefresherBuilder
    {
        private readonly string _refreshEndpoint;
        private readonly string _localKeyHandle;
        private HttpClient? _http;
        private IKeyStore? _keyStore;
        private Discovery.AAuthEgressPolicy _egressPolicy = Discovery.AAuthEgressPolicy.Production;

        /// <summary>Configure admission for the internally created refresh client.</summary>
        public RefresherBuilder WithEgressPolicy(Discovery.AAuthEgressPolicy policy)
        {
            _egressPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
            return this;
        }

        internal RefresherBuilder(string refreshEndpoint, string localKeyHandle)
        {
            ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
            ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);
            _refreshEndpoint = refreshEndpoint;
            _localKeyHandle = localKeyHandle;
        }

        /// <summary>Use a custom <see cref="HttpClient"/> instead of creating one internally.</summary>
        public RefresherBuilder WithHttpClient(HttpClient http) { _http = http ?? throw new ArgumentNullException(nameof(http)); return this; }

        /// <summary>Use a custom <see cref="IKeyStore"/> instead of <see cref="FileKeyStore.Default()"/>.</summary>
        public RefresherBuilder WithKeyStore(IKeyStore keyStore) { _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore)); return this; }

        /// <summary>Build a disposable refresher. It owns only the client it creates.</summary>
        public AgentProviderTokenRefresher Build()
        {
            var keyStore = _keyStore ?? FileKeyStore.Default();
            var http = _http ?? Discovery.AAuthHttpTransport.CreateClient(_egressPolicy);
            return new(http, keyStore, _refreshEndpoint, _localKeyHandle)
            {
                _ownedHttp = _http is null ? http : null,
            };
        }

        /// <summary>Implicit conversion so the builder can be passed directly where <see cref="ITokenRefresher"/> is expected.</summary>
        public static implicit operator AgentProviderTokenRefresher(RefresherBuilder b) => b.Build();
    }
}
