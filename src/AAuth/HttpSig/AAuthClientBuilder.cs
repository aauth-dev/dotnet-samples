using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;

namespace AAuth.HttpSig;

/// <summary>
/// Fluent builder for creating an <see cref="HttpClient"/> that signs every
/// outbound request with one of the AAuth signing modes.
/// </summary>
/// <example>
/// <code>
/// using var client = new AAuthClientBuilder(key)
///     .UseHwk()
///     .Build();
/// </code>
/// </example>
public sealed class AAuthClientBuilder
{
    private readonly IAAuthKey _key;
    private ISignatureKeyProvider? _provider;
    private HttpMessageHandler? _innerHandler;
    private IReadOnlyList<string>? _capabilities;
    private Action<HttpRequestMessage, string>? _onSignatureBase;

    // Challenge handling state
    private bool _challengeHandling;
    private string? _personServer;
    private Action<ChallengeHandlingOptions>? _challengeOptionsConfigure;

    // Token refresh state
    private ITokenRefresher? _tokenRefresher;
    private TimeSpan? _refreshThreshold;

    // Stored token (for reading claims)
    private string? _agentToken;
    private Func<string>? _tokenFactory;

    public AAuthClientBuilder(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
    }

    /// <summary>Use the pseudonymous (hwk) signing mode.</summary>
    public AAuthClientBuilder UseHwk()
    {
        _provider = new HwkSignatureKeyProvider(_key);
        return this;
    }

    /// <summary>Use the Agent Token (jwt) signing mode.</summary>
    /// <param name="tokenFactory">Returns the agent token JWT for each request.</param>
    public AAuthClientBuilder UseJwt(Func<string> tokenFactory)
    {
        _tokenFactory = tokenFactory;
        _agentToken = tokenFactory();
        _provider = new JwtSignatureKeyProvider(tokenFactory);
        return this;
    }

    /// <summary>Use the Agent Token (jwt) signing mode with a fixed token.</summary>
    /// <param name="agentToken">The agent token JWT.</param>
    public AAuthClientBuilder UseJwt(string agentToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentToken);
        _agentToken = agentToken;
        _tokenFactory = () => agentToken;
        _provider = new JwtSignatureKeyProvider(_tokenFactory);
        return this;
    }

    /// <summary>Use the Agent Identity (jwks_uri) signing mode.</summary>
    /// <param name="uri">JWKS endpoint URL where the verifier can fetch the public key.</param>
    /// <param name="kid">Key ID within the JWKS.</param>
    public AAuthClientBuilder UseJwksUri(string uri, string kid)
    {
        _provider = new JwksUriSignatureKeyProvider(uri, kid);
        return this;
    }

    /// <summary>Use the two-key delegation (jkt-jwt) signing mode.</summary>
    /// <param name="namingJwtFactory">Returns the naming JWT (signed by the durable key) for each request.</param>
    public AAuthClientBuilder UseJktJwt(Func<string> namingJwtFactory)
    {
        _provider = new JktJwtSignatureKeyProvider(_key, namingJwtFactory);
        return this;
    }

    /// <summary>Use a custom <see cref="ISignatureKeyProvider"/> implementation.</summary>
    public AAuthClientBuilder UseProvider(ISignatureKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _provider = provider;
        return this;
    }

    /// <summary>Override the inner HTTP handler (defaults to <see cref="HttpClientHandler"/>).</summary>
    public AAuthClientBuilder WithInnerHandler(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _innerHandler = handler;
        return this;
    }

    /// <summary>Declare AAuth-Capabilities on every signed request.</summary>
    public AAuthClientBuilder WithCapabilities(params string[] capabilities)
    {
        _capabilities = capabilities;
        return this;
    }

    /// <summary>Attach an observability hook for the RFC 9421 signature base string.</summary>
    public AAuthClientBuilder OnSignatureBase(Action<HttpRequestMessage, string> callback)
    {
        _onSignatureBase = callback;
        return this;
    }

    /// <summary>
    /// Enable automatic 401 challenge handling. The Person Server URL is
    /// extracted from the agent token's <c>ps</c> claim.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling()
    {
        _challengeHandling = true;
        _personServer = null;
        return this;
    }

    /// <summary>
    /// Enable automatic 401 challenge handling with an explicit Person Server URL.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling(string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _challengeHandling = true;
        _personServer = personServer;
        return this;
    }

    /// <summary>
    /// Enable automatic 401 challenge handling with an explicit Person Server
    /// URL and additional options.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling(string personServer, Action<ChallengeHandlingOptions> configure)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentNullException.ThrowIfNull(configure);
        _challengeHandling = true;
        _personServer = personServer;
        _challengeOptionsConfigure = configure;
        return this;
    }

    /// <summary>
    /// Register a custom token refresher that is invoked when the agent
    /// token nears expiry.
    /// </summary>
    public AAuthClientBuilder WithTokenRefresh(ITokenRefresher refresher, TimeSpan? refreshThreshold = null)
    {
        ArgumentNullException.ThrowIfNull(refresher);
        _tokenRefresher = refresher;
        _refreshThreshold = refreshThreshold;
        return this;
    }

    /// <summary>
    /// Register a token refresh callback invoked when the agent token nears expiry.
    /// </summary>
    public AAuthClientBuilder WithTokenRefresh(Func<TokenRefreshContext, CancellationToken, Task<string>> refreshFunc, TimeSpan? refreshThreshold = null)
    {
        ArgumentNullException.ThrowIfNull(refreshFunc);
        _tokenRefresher = new DelegateTokenRefresher(refreshFunc);
        _refreshThreshold = refreshThreshold;
        return this;
    }

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpClient Build()
    {
        if (_provider is null)
            throw new InvalidOperationException(
                "A signing mode must be configured. Call UseHwk(), UseJwt(), UseJwksUri(), or UseJktJwt() before Build().");

        if (!_challengeHandling)
        {
            // Simple signing-only pipeline.
            var handler = new AAuthSigningHandler(_key, _provider)
            {
                InnerHandler = _innerHandler ?? new HttpClientHandler(),
                Capabilities = _capabilities,
                OnSignatureBase = _onSignatureBase,
            };
            return new HttpClient(handler);
        }

        // --- Challenge-handling pipeline ---
        var agentToken = ResolveAgentToken();
        var personServer = ResolvePersonServer(agentToken);

        var challengeOptions = new ChallengeHandlingOptions();
        _challengeOptionsConfigure?.Invoke(challengeOptions);

        // The token holder starts with the agent token.
        var tokenHolder = new AAuthTokenHolder(agentToken);

        // Build the token factory that reads from the holder (so after refresh
        // or exchange, the signing handler uses the updated token).
        var holderProvider = new JwtSignatureKeyProvider(() => tokenHolder.Current);

        // Outer signing handler (signs requests to resources).
        var outerSigner = new AAuthSigningHandler(_key, holderProvider)
        {
            InnerHandler = _innerHandler ?? new HttpClientHandler(),
            Capabilities = MergeCapabilities("auth-token"),
            OnSignatureBase = _onSignatureBase,
        };

        // Exchange pipeline: separate signing handler pinned to the agent token.
        var exchangeSigner = new AAuthSigningHandler(_key, _provider)
        {
            InnerHandler = new HttpClientHandler(),
        };
        var exchangeHttpClient = new HttpClient(exchangeSigner);
        var metadataHttp = new HttpClient();
        var metadata = new MetadataClient(metadataHttp);
        var exchangeClient = new TokenExchangeClient(exchangeHttpClient, metadata);

        var pollerOptions = new DeferredPollerOptions
        {
            MaxTotalWait = challengeOptions.PollingTimeout,
            DefaultPollInterval = challengeOptions.DefaultPollInterval,
        };

        // Challenge handler sits above the outer signer.
        var challengeHandler = new ChallengeHandler(
            exchangeClient, tokenHolder, personServer,
            challengeOptions.OnInteractionRequired, pollerOptions)
        {
            InnerHandler = outerSigner,
        };

        // If token refresh is configured, insert it above the challenge handler.
        HttpMessageHandler topHandler = challengeHandler;
        if (_tokenRefresher is not null)
        {
            var keyId = _key.ComputeJwkThumbprint();
            var refreshHandler = new TokenRefreshHandler(tokenHolder, _tokenRefresher, keyId, _refreshThreshold)
            {
                InnerHandler = challengeHandler,
            };
            topHandler = refreshHandler;
        }

        return new HttpClient(topHandler);
    }

    private string ResolveAgentToken()
    {
        if (_agentToken is not null)
            return _agentToken;
        if (_tokenFactory is not null)
            return _tokenFactory();
        throw new InvalidOperationException(
            "WithChallengeHandling() requires an agent token. Call UseJwt() before WithChallengeHandling().");
    }

    private string ResolvePersonServer(string agentToken)
    {
        if (_personServer is not null)
            return _personServer;

        // Read the 'ps' claim from the agent token payload.
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(agentToken);
        var ps = (string?)payload["ps"];
        if (string.IsNullOrEmpty(ps))
            throw new InvalidOperationException(
                "Cannot resolve Person Server: agent token does not contain a 'ps' claim. " +
                "Provide an explicit personServer URL via WithChallengeHandling(personServer).");
        return ps;
    }

    private IReadOnlyList<string>? MergeCapabilities(string required)
    {
        if (_capabilities is null || _capabilities.Count == 0)
            return new[] { required };

        var list = new List<string>(_capabilities);
        if (!list.Contains(required))
            list.Add(required);
        return list;
    }
}

internal sealed class DelegateTokenRefresher : ITokenRefresher
{
    private readonly Func<TokenRefreshContext, CancellationToken, Task<string>> _func;

    public DelegateTokenRefresher(Func<TokenRefreshContext, CancellationToken, Task<string>> func)
    {
        _func = func;
    }

    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
        => _func(context, cancellationToken);
}
