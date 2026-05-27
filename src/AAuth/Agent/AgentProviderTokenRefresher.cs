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
/// The AP identifies the agent by verifying the HTTP signature against the
/// enrolled key (looked up by thumbprint).
/// </remarks>
public sealed class AgentProviderTokenRefresher : ITokenRefresher
{
    private readonly AgentProviderClient _client;
    private readonly string _refreshEndpoint;
    private readonly string _enrolledKeyId;

    /// <summary>Create a refresher that delegates to an Agent Provider.</summary>
    /// <param name="http">HttpClient for AP communication (reused across refreshes).</param>
    /// <param name="keyStore">Key store containing the agent's durable signing key.</param>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    /// <param name="enrolledKeyId">Local keystore reference assigned during enrollment. Used to load the private key for signing refresh requests. The AP identifies the agent by verifying the signature (matching the JWK thumbprint), not by receiving this string.</param>
    public AgentProviderTokenRefresher(HttpClient http, IKeyStore keyStore, string refreshEndpoint, string enrolledKeyId)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(enrolledKeyId);
        _client = new AgentProviderClient(http, keyStore);
        _refreshEndpoint = refreshEndpoint;
        _enrolledKeyId = enrolledKeyId;
    }

    /// <summary>Start building a refresher with required parameters.</summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    /// <param name="enrolledKeyId">Local keystore reference for the durable signing key (assigned during enrollment).</param>
    public static RefresherBuilder Create(string refreshEndpoint, string enrolledKeyId) => new(refreshEndpoint, enrolledKeyId);

    /// <inheritdoc/>
    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _client.RefreshAsync(_refreshEndpoint, _enrolledKeyId, cancellationToken);
    }

    /// <summary>Fluent builder for <see cref="AgentProviderTokenRefresher"/>.</summary>
    public sealed class RefresherBuilder
    {
        private readonly string _refreshEndpoint;
        private readonly string _enrolledKeyId;
        private HttpClient? _http;
        private IKeyStore? _keyStore;

        internal RefresherBuilder(string refreshEndpoint, string enrolledKeyId)
        {
            ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
            ArgumentException.ThrowIfNullOrEmpty(enrolledKeyId);
            _refreshEndpoint = refreshEndpoint;
            _enrolledKeyId = enrolledKeyId;
        }

        /// <summary>Use a custom <see cref="HttpClient"/> instead of creating one internally.</summary>
        public RefresherBuilder WithHttpClient(HttpClient http) { _http = http; return this; }

        /// <summary>Use a custom <see cref="IKeyStore"/> instead of <see cref="FileKeyStore.Default()"/>.</summary>
        public RefresherBuilder WithKeyStore(IKeyStore keyStore) { _keyStore = keyStore; return this; }

        /// <summary>Build the refresher.</summary>
        public AgentProviderTokenRefresher Build()
            => new(_http ?? new HttpClient(), _keyStore ?? FileKeyStore.Default(), _refreshEndpoint, _enrolledKeyId);

        /// <summary>Implicit conversion so the builder can be passed directly where <see cref="ITokenRefresher"/> is expected.</summary>
        public static implicit operator AgentProviderTokenRefresher(RefresherBuilder b) => b.Build();
    }
}
