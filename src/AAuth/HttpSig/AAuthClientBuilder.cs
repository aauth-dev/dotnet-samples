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

    /// <summary>
    /// Start a bootstrap enrollment flow. Returns a <see cref="BootstrapBuilder"/>
    /// that enrols with the AP and returns an <see cref="EnrollResult"/>.
    /// Use the result with <see cref="AAuthClientBuilder"/> to build a client separately.
    /// </summary>
    /// <param name="enrollEndpoint">The AP's enrollment endpoint URL (not discoverable from metadata).</param>
    /// <param name="agentId">Desired agent identifier (e.g. <c>aauth:myagent@example.com</c>).</param>
    public static BootstrapBuilder Bootstrap(string enrollEndpoint, string agentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(enrollEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        return new BootstrapBuilder(enrollEndpoint, agentId);
    }

    // Challenge handling state
    private bool _challengeHandling;
    private string? _personServer;
    private Action<ChallengeHandlingOptions>? _challengeOptionsConfigure;

    // Token refresh state
    private ITokenRefresher? _tokenRefresher;
    private TimeSpan? _refreshThreshold;

    // Interaction handling state
    private bool _interactionHandling;
    private Action<InteractionHandlingOptions>? _interactionOptionsConfigure;

    // Call-chaining state
    private Func<string?>? _upstreamTokenProvider;

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

    /// <summary>
    /// Use the JWT signing mode with a token factory. Each request calls
    /// <paramref name="tokenFactory"/> to get the current token.
    /// For lazy acquisition via the AP refresh endpoint, prefer
    /// <see cref="WithTokenRefresh(ITokenRefresher, TimeSpan?)"/>.
    /// For call-chaining where you already have a chained auth token,
    /// use <see cref="UseJwt(string)"/>.
    /// </summary>
    public AAuthClientBuilder UseJwt(Func<string> tokenFactory)
    {
        _tokenFactory = tokenFactory;
        _agentToken = tokenFactory();
        _provider = new JwtSignatureKeyProvider(tokenFactory);
        return this;
    }

    /// <summary>
    /// Use the JWT signing mode with a fixed token string. Ideal for
    /// call-chaining scenarios where the Orchestrator has already obtained
    /// a chained auth token via <c>upstream_token</c> exchange.
    /// </summary>
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
    /// Enable automatic 401 challenge handling with options. The Person Server URL is
    /// extracted from the agent token's <c>ps</c> claim.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _challengeHandling = true;
        _personServer = null;
        _challengeOptionsConfigure = configure;
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

    /// <summary>
    /// Enable automatic handling of 202 responses with
    /// <c>requirement=interaction</c> or <c>requirement=approval</c>.
    /// </summary>
    public AAuthClientBuilder WithInteractionHandling(Action<InteractionHandlingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _interactionHandling = true;
        _interactionOptionsConfigure = configure;
        return this;
    }

    /// <summary>
    /// Enable automatic handling of 202 responses with
    /// <c>requirement=interaction</c> or <c>requirement=approval</c> (default options).
    /// </summary>
    public AAuthClientBuilder WithInteractionHandling()
    {
        _interactionHandling = true;
        return this;
    }

    /// <summary>
    /// Enable call-chaining: when the client receives a 401 challenge from a
    /// downstream resource, the SDK exchanges the resource token at the
    /// PS/AS resolved per §Call Chaining of the AAuth specification and
    /// passes the supplied upstream auth token as <c>upstream_token</c>
    /// so the PS can build the nested <c>act</c> claim (§Upstream Token
    /// Verification). Combine with <see cref="WithChallengeHandling()"/>.
    /// </summary>
    /// <param name="upstreamTokenProvider">
    /// Provider invoked per challenge that returns the inbound (caller's)
    /// auth token to forward. May return <see langword="null"/> to indicate
    /// no upstream context is available, in which case the embedded exchange
    /// falls back to the configured Person Server.
    /// </param>
    public AAuthClientBuilder WithCallChaining(Func<string?> upstreamTokenProvider)
    {
        ArgumentNullException.ThrowIfNull(upstreamTokenProvider);
        _upstreamTokenProvider = upstreamTokenProvider;
        return this;
    }

    /// <summary>
    /// Enable call-chaining with a fixed upstream auth token (e.g. one the
    /// caller has captured from <c>HttpContext.Features</c>).
    /// </summary>
    public AAuthClientBuilder WithCallChaining(string upstreamAuthToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);
        _upstreamTokenProvider = () => upstreamAuthToken;
        return this;
    }

    /// <summary>
    /// Enable call-chaining sourced from the current ASP.NET Core request:
    /// reads the verified upstream <c>aa-auth+jwt</c> from
    /// <see cref="Microsoft.AspNetCore.Http.HttpContext.Features"/> (set
    /// by <see cref="Server.AAuthVerificationMiddleware"/>) when the
    /// downstream challenge fires.
    /// </summary>
    public AAuthClientBuilder WithCallChaining(Microsoft.AspNetCore.Http.HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        _upstreamTokenProvider = () =>
            httpContext.Features.Get<Server.UpstreamAuthTokenFeature>()?.Token;
        return this;
    }

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpClient Build() => new HttpClient(BuildHandler());

    /// <summary>
    /// Build the configured handler pipeline without wrapping it in an <see cref="HttpClient"/>.
    /// Useful for DI registration via <c>ConfigurePrimaryHttpMessageHandler</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpMessageHandler BuildHandler()
    {
        if (_provider is null && _tokenRefresher is null)
            throw new InvalidOperationException(
                "A signing mode must be configured. Call UseHwk(), UseJwksUri(), or UseJktJwt() before Build(), or use WithTokenRefresh() for JWT mode.");

        if (!_challengeHandling && _upstreamTokenProvider is null)
        {
            // When WithTokenRefresh is configured but no explicit provider,
            // create a JWT signing pipeline with lazy token acquisition.
            if (_provider is null && _tokenRefresher is not null)
                return BuildRefreshOnlyHandler();

            // Simple signing-only pipeline (possibly with interaction handling).
            var handler = new AAuthSigningHandler(_key, _provider!)
            {
                InnerHandler = _innerHandler ?? new HttpClientHandler(),
                Capabilities = _interactionHandling ? MergeCapabilities("interaction") : _capabilities,
                OnSignatureBase = _onSignatureBase,
            };

            if (!_interactionHandling)
                return handler;

            // Wrap with interaction handler
            var interactionOpts = new InteractionHandlingOptions();
            _interactionOptionsConfigure?.Invoke(interactionOpts);
            var interactionHandler = new InteractionHandler(
                interactionOpts.OnInteractionRequired,
                interactionOpts.OnApprovalPending,
                interactionOpts.PollingTimeout)
            {
                InnerHandler = handler,
            };
            return interactionHandler;
        }

        // --- Challenge-handling pipeline ---
        var agentToken = ResolveAgentToken();
        var personServer = _upstreamTokenProvider is not null
            ? ResolvePersonServerOptional(agentToken)
            : ResolvePersonServer(agentToken);

        var challengeOptions = new ChallengeHandlingOptions();
        _challengeOptionsConfigure?.Invoke(challengeOptions);

        // The token holder starts with the agent token (or empty for lazy acquisition).
        var tokenHolder = agentToken is not null
            ? new AAuthTokenHolder(agentToken)
            : new AAuthTokenHolder();

        // Build the token factory that reads from the holder (so after refresh
        // or exchange, the signing handler uses the updated token).
        var holderProvider = new JwtSignatureKeyProvider(() => tokenHolder.Current);

        // Outer signing handler (signs requests to resources).
        var outerSigner = new AAuthSigningHandler(_key, holderProvider)
        {
            InnerHandler = _innerHandler ?? new HttpClientHandler(),
            Capabilities = _interactionHandling
                ? MergeCapabilities("auth-token", "interaction")
                : MergeCapabilities("auth-token"),
            OnSignatureBase = _onSignatureBase,
        };

        // Exchange pipeline: separate signing handler pinned to the agent token.
        var exchangeProvider = _provider ?? holderProvider;
        var exchangeSigner = new AAuthSigningHandler(_key, exchangeProvider)
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
            PreferWaitSeconds = challengeOptions.PreferWaitSeconds,
        };

        // Challenge handler sits above the outer signer.
        var challengeHandler = new ChallengeHandler(
            exchangeClient, tokenHolder, personServer,
            challengeOptions.OnInteractionRequired, pollerOptions,
            upstreamTokenProvider: _upstreamTokenProvider)
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

        // If interaction handling is configured, insert it at the top.
        if (_interactionHandling)
        {
            var interactionOpts = new InteractionHandlingOptions();
            _interactionOptionsConfigure?.Invoke(interactionOpts);
            var interactionHandler = new InteractionHandler(
                interactionOpts.OnInteractionRequired,
                interactionOpts.OnApprovalPending,
                interactionOpts.PollingTimeout)
            {
                InnerHandler = topHandler,
            };
            topHandler = interactionHandler;
        }

        return topHandler;
    }

    private HttpMessageHandler BuildRefreshOnlyHandler()
    {
        var holder = new AAuthTokenHolder();
        var provider = new JwtSignatureKeyProvider(() => holder.Current);
        var keyId = _key.ComputeJwkThumbprint();

        var signingHandler = new AAuthSigningHandler(_key, provider)
        {
            InnerHandler = _innerHandler ?? new HttpClientHandler(),
            Capabilities = _capabilities,
            OnSignatureBase = _onSignatureBase,
        };

        var refreshHandler = new TokenRefreshHandler(holder, _tokenRefresher!, keyId, _refreshThreshold)
        {
            InnerHandler = signingHandler,
        };

        if (!_interactionHandling)
            return refreshHandler;

        var opts = new InteractionHandlingOptions();
        _interactionOptionsConfigure?.Invoke(opts);
        return new InteractionHandler(
            opts.OnInteractionRequired,
            opts.OnApprovalPending,
            opts.PollingTimeout)
        {
            InnerHandler = refreshHandler,
        };
    }

    private string? ResolveAgentToken()
    {
        if (_agentToken is not null)
            return _agentToken;
        if (_tokenFactory is not null)
            return _tokenFactory();

        // Lazy acquisition: no token provided, but WithTokenRefresh will fetch one
        // on the first request. Return null to signal the holder should start empty.
        if (_tokenRefresher is not null)
            return null;

        throw new InvalidOperationException(
            "WithChallengeHandling() requires a token source. " +
            "Configure WithTokenRefresh() for lazy token acquisition.");
    }

    private string? ResolvePersonServerOptional(string? agentToken)
    {
        if (_personServer is not null) return _personServer;
        if (agentToken is null) return null;
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(agentToken);
        return (string?)payload["ps"];
    }

    private string ResolvePersonServer(string? agentToken)
    {
        if (_personServer is not null)
            return _personServer;

        if (agentToken is null)
            throw new InvalidOperationException(
                "Cannot resolve Person Server without an agent token. " +
                "Provide an explicit personServer URL via WithChallengeHandling(personServer) when using lazy token acquisition.");

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

    private IReadOnlyList<string> MergeCapabilities(string required1, string required2)
    {
        var list = _capabilities is null || _capabilities.Count == 0
            ? new List<string>()
            : new List<string>(_capabilities);
        if (!list.Contains(required1))
            list.Add(required1);
        if (!list.Contains(required2))
            list.Add(required2);
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
