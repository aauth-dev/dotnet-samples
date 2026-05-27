using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Agent;

/// <summary>Refresh mode for AP token refresh.</summary>
public enum RefreshMode
{
    /// <summary>
    /// Single-key refresh: signs the refresh POST with the durable key under <c>hwk</c> scheme.
    /// The AP returns a token whose <c>cnf.jwk</c> is the same durable key.
    /// </summary>
    SingleKey,

    /// <summary>
    /// Two-key refresh: generates a fresh ephemeral key, creates a naming JWT signed by
    /// the durable key, signs the refresh POST with the ephemeral key under <c>jkt-jwt</c> scheme.
    /// The AP returns a token whose <c>cnf.jwk</c> is the new ephemeral key.
    /// </summary>
    TwoKey,
}

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
public sealed class AgentProviderTokenRefresher : ITokenRefresher
{
    private readonly AgentProviderClient _client;
    private readonly string _refreshEndpoint;
    private readonly string _localKeyHandle;
    private readonly RefreshMode _mode;
    private readonly string? _apIssuer;

    /// <summary>
    /// The latest ephemeral key produced by a two-key refresh.
    /// Null when <see cref="RefreshMode.SingleKey"/> is used or before the first refresh.
    /// </summary>
    public AAuthKey? LatestEphemeralKey { get; private set; }

    /// <summary>Create a refresher that delegates to an Agent Provider.</summary>
    public AgentProviderTokenRefresher(
        HttpClient http,
        IKeyStore keyStore,
        string refreshEndpoint,
        string localKeyHandle,
        RefreshMode mode = RefreshMode.SingleKey,
        string? apIssuer = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);
        if (mode == RefreshMode.TwoKey && string.IsNullOrEmpty(apIssuer))
            throw new ArgumentException("apIssuer is required for TwoKey refresh mode.", nameof(apIssuer));
        _client = new AgentProviderClient(http, keyStore);
        _refreshEndpoint = refreshEndpoint;
        _localKeyHandle = localKeyHandle;
        _mode = mode;
        _apIssuer = apIssuer;
    }

    /// <summary>Start building a refresher with required parameters.</summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    /// <param name="localKeyHandle">Agent-local <see cref="IKeyStore"/> handle for the durable signing key (assigned during enrollment).</param>
    public static RefresherBuilder Create(string refreshEndpoint, string localKeyHandle) => new(refreshEndpoint, localKeyHandle);

    /// <inheritdoc/>
    public async Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (_mode == RefreshMode.TwoKey)
        {
            var result = await _client.RefreshTwoKeyAsync(_refreshEndpoint, _localKeyHandle, _apIssuer!, cancellationToken);
            LatestEphemeralKey = result.EphemeralKey;
            return result.AgentToken;
        }
        return await _client.RefreshAsync(_refreshEndpoint, _localKeyHandle, cancellationToken);
    }

    /// <summary>Fluent builder for <see cref="AgentProviderTokenRefresher"/>.</summary>
    public sealed class RefresherBuilder
    {
        private readonly string _refreshEndpoint;
        private readonly string _localKeyHandle;
        private HttpClient? _http;
        private IKeyStore? _keyStore;
        private RefreshMode _mode = RefreshMode.SingleKey;
        private string? _apIssuer;

        internal RefresherBuilder(string refreshEndpoint, string localKeyHandle)
        {
            ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
            ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);
            _refreshEndpoint = refreshEndpoint;
            _localKeyHandle = localKeyHandle;
        }

        /// <summary>Use a custom <see cref="HttpClient"/> instead of creating one internally.</summary>
        public RefresherBuilder WithHttpClient(HttpClient http) { _http = http; return this; }

        /// <summary>Use a custom <see cref="IKeyStore"/> instead of <see cref="FileKeyStore.Default()"/>.</summary>
        public RefresherBuilder WithKeyStore(IKeyStore keyStore) { _keyStore = keyStore; return this; }

        /// <summary>Set the refresh mode. Default is <see cref="RefreshMode.SingleKey"/>.</summary>
        /// <param name="mode">Refresh mode to use.</param>
        /// <param name="apIssuer">AP issuer URL (required for <see cref="RefreshMode.TwoKey"/>).</param>
        public RefresherBuilder WithRefreshMode(RefreshMode mode, string? apIssuer = null)
        {
            _mode = mode;
            _apIssuer = apIssuer;
            return this;
        }

        /// <summary>Build the refresher.</summary>
        public AgentProviderTokenRefresher Build()
            => new(_http ?? new HttpClient(), _keyStore ?? FileKeyStore.Default(), _refreshEndpoint, _localKeyHandle, _mode, _apIssuer);

        /// <summary>Implicit conversion so the builder can be passed directly where <see cref="ITokenRefresher"/> is expected.</summary>
        public static implicit operator AgentProviderTokenRefresher(RefresherBuilder b) => b.Build();
    }
}
