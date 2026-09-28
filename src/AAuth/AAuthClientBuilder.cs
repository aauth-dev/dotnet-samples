using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.CallChaining;
using Microsoft.AspNetCore.Http;

namespace AAuth;

/// <summary>
/// Fluent builder for creating an <see cref="HttpClient"/> that signs every
/// outbound request with a Signature-Key scheme. Resource access modes and
/// agent provisioning are configured independently.
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
    private AAuthEgressPolicy _egressPolicy = AAuthEgressPolicy.Production;
    private AAuthTransportContract? _transportContract;

    public AAuthClientBuilder WithEgressPolicy(AAuthEgressPolicy policy)
    {
        _egressPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
        return this;
    }

    public AAuthClientBuilder WithDevelopmentLoopback(params string[] origins) =>
        WithEgressPolicy(AAuthEgressPolicy.ForDevelopmentLoopback(origins));

    private HttpMessageHandler CreateTransport() =>
        AAuthHttpTransport.CreateHandler(_egressPolicy, _innerHandler, _transportContract);
    private IReadOnlyList<string>? _capabilities;
    private Action<HttpRequestMessage, string>? _onSignatureBase;

    /// <summary>
    /// Start a bootstrap enrollment flow. Returns a <see cref="BootstrapBuilder"/>
    /// that enrols with the AP and returns an <see cref="EnrollResult"/>.
    /// Use the result with <see cref="AAuthClientBuilder"/> to build a client separately.
    /// </summary>
    /// <param name="enrollEndpoint">The AP's enrollment endpoint URL, advertised in its metadata.</param>
    /// <param name="agentId">Desired agent identifier, or null for provider-assigned identity.</param>
    public static BootstrapBuilder Bootstrap(string enrollEndpoint, string? agentId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(enrollEndpoint);
        if (agentId is not null) ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        return new BootstrapBuilder(enrollEndpoint, agentId);
    }

    /// <summary>
    /// Create a builder pre-configured from an <see cref="EnrollResult"/>.
    /// Uses the issued agent token with the <c>jwt</c> Signature-Key scheme.
    /// Does not enroll or refresh implicitly. Add <see cref="WithTokenRefresh(ITokenRefresher, TimeSpan?)"/>
    /// for renewal, or select another scheme explicitly. Flow options never select a scheme.
    /// </summary>
    /// <param name="result">The enrollment result from <see cref="AgentProviderClient.EnrolAsync"/>.</param>
    public static AAuthClientBuilder From(EnrollResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new AAuthClientBuilder(result.Key).UseJwt(result.AgentToken);
    }

    // Challenge handling state
    private bool _challengeHandling;
    private string? _personServer;
    private Action<ChallengeHandlingOptions>? _challengeOptionsConfigure;

    // Self-issued token state
    private string? _selfIssuedPersonServer;
    private string? _selfIssuedIssuer;
    private string? _selfIssuedSubject;
    private string? _selfIssuedKid;

    // Call-chaining state
    private Func<string?>? _upstreamTokenProvider;

    // Mission state (originating agent's own approved mission)
    private Agent.Mission? _mission;

    // Token refresh state
    private ITokenRefresher? _tokenRefresher;
    private Func<AAuthEgressPolicy, ITokenRefresher>? _ownedTokenRefresherFactory;
    private TimeSpan? _refreshThreshold;

    // Interaction handling state
    private bool _interactionHandling;
    private Action<InteractionHandlingOptions>? _interactionOptionsConfigure;

    // Resource-managed (AAuth-Access) opaque-token state
    private bool _resourceManagedAccess;
    private IAAuthAccessStore? _accessStore;

    // Stored token (for reading claims)
    private string? _agentToken;
    private Func<string>? _tokenFactory;

    public AAuthClientBuilder(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
    }

    /// <summary>
    /// Start building a self-issued agent identity with a fluent sub-builder.
    /// Call <see cref="SelfIssuingBuilder.As"/> to set issuer and subject.
    /// </summary>
    /// <param name="key">The agent's signing key.</param>
    /// <example>
    /// <code>
    /// using var client = AAuthClientBuilder.SelfIssuing(key)
    ///     .As(issuer, subject)
    ///     .WithPersonServer(ps)
    ///     .Build();
    /// </code>
    /// </example>
    public static SelfIssuingBuilder SelfIssuing(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new SelfIssuingBuilder(key);
    }

    /// <summary>
    /// Start building an AP-enrolled agent client with a fluent sub-builder.
    /// Call <see cref="EnrolledBuilder.RefreshingFrom"/> to set the refresh endpoint.
    /// </summary>
    /// <param name="key">The agent's durable signing key (loaded from the key store).</param>
    /// <example>
    /// <code>
    /// using var client = AAuthClientBuilder.Enrolled(key)
    ///     .RefreshingFrom(refreshEndpoint, localKeyHandle)
    ///     .WithKeyStore(keyStore)
    ///     .WithChallengeHandling(ps)
    ///     .Build();
    /// </code>
    /// </example>
    public static EnrolledBuilder Enrolled(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new EnrolledBuilder(key);
    }

    /// <summary>Use the pseudonymous (hwk) signing mode.</summary>
    public AAuthClientBuilder UseHwk()
    {
        ClearTokenRefresh();
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
        ArgumentNullException.ThrowIfNull(tokenFactory);
        ClearTokenRefresh();
        _tokenFactory = tokenFactory;
        _provider = new JwtSignatureKeyProvider(tokenFactory);
        return this;
    }

    /// <summary>
    /// Use the JWT signing mode with a fixed token string. Ideal for
    /// call-chaining scenarios where the Orchestrator has already obtained
    /// a chained auth token via <c>upstream_token</c> exchange.
    /// </summary>
    public AAuthClientBuilder UseJwt(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        ClearTokenRefresh();
        _agentToken = token;
        _tokenFactory = () => token;
        _provider = new JwtSignatureKeyProvider(_tokenFactory);
        return this;
    }

    /// <summary>Use server identity and metadata discovery.</summary>
    /// <param name="id">Signer identifier.</param>
    /// <param name="dwk">Well-known metadata document name.</param>
    /// <param name="kid">Key ID within the JWKS.</param>
    public AAuthClientBuilder UseJwksUri(string id, string dwk, string kid)
    {
        ClearTokenRefresh();
        _provider = new JwksUriSignatureKeyProvider(id, dwk, kid);
        return this;
    }

    public AAuthClientBuilder UseJwks(string url, string kid)
    {
        ClearTokenRefresh();
        _provider = new JwksSignatureKeyProvider(url, kid);
        return this;
    }

    public AAuthClientBuilder UseSelfJwt(Func<string> tokenFactory)
    {
        ClearTokenRefresh();
        _provider = new SelfJwtSignatureKeyProvider(tokenFactory);
        return this;
    }

    /// <summary>Use the self-issued two-key delegation (jkt-jwt) signing mode.</summary>
    /// <param name="namingJwtFactory">Returns the <c>jkt-s256+jwt</c> delegation JWT (signed by the durable key) for each request.</param>
    public AAuthClientBuilder UseJktJwt(Func<string> namingJwtFactory)
    {
        ClearTokenRefresh();
        _provider = new JktJwtSignatureKeyProvider(namingJwtFactory);
        return this;
    }

    /// <summary>Use a custom <see cref="ISignatureKeyProvider"/> implementation.</summary>
    public AAuthClientBuilder UseProvider(ISignatureKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ClearTokenRefresh();
        _provider = provider;
        return this;
    }

    /// <summary>Override the inner HTTP handler (defaults to <see cref="HttpClientHandler"/>).</summary>
    public AAuthClientBuilder WithInnerHandler(HttpMessageHandler handler, AAuthTransportContract? transportContract = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _innerHandler = handler;
        _transportContract = transportContract;
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
    /// extracted from the agent token's <c>ps</c> claim, or from
    /// <see cref="WithPersonServer"/> if previously configured.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling()
    {
        _challengeHandling = true;
        return this;
    }

    /// <summary>
    /// Enable automatic 401 challenge handling with options. The Person Server URL is
    /// extracted from the agent token's <c>ps</c> claim, or from
    /// <see cref="WithPersonServer"/> if previously configured.
    /// </summary>
    public AAuthClientBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _challengeHandling = true;
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
    /// Enable call-chaining with a delegate that provides the upstream auth token.
    /// Implicitly enables challenge handling; <c>personServer</c> becomes optional
    /// (resolved from the upstream token at runtime via <see cref="CallChainingRouter"/>).
    /// </summary>
    /// <param name="upstreamTokenProvider">Returns the upstream <c>aa-auth+jwt</c>, or null if unavailable.</param>
    public AAuthClientBuilder WithCallChaining(Func<string?> upstreamTokenProvider)
    {
        ArgumentNullException.ThrowIfNull(upstreamTokenProvider);
        _upstreamTokenProvider = upstreamTokenProvider;
        _challengeHandling = true;
        return this;
    }

    /// <summary>
    /// Enable call-chaining with a fixed upstream auth token (captured at construction time).
    /// Implicitly enables challenge handling.
    /// </summary>
    /// <param name="upstreamAuthToken">The upstream <c>aa-auth+jwt</c> token string.</param>
    public AAuthClientBuilder WithCallChaining(string upstreamAuthToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);
        _upstreamTokenProvider = () => upstreamAuthToken;
        _challengeHandling = true;
        return this;
    }

    /// <summary>
    /// Enable call-chaining by reading the upstream auth token from
    /// <see cref="UpstreamAuthTokenFeature"/> on the given <see cref="HttpContext"/>.
    /// Implicitly enables challenge handling.
    /// </summary>
    /// <param name="httpContext">The current HTTP context (must have been verified by <see cref="AAuthVerificationMiddleware"/>).</param>
    public AAuthClientBuilder WithCallChaining(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        _upstreamTokenProvider = () => httpContext.Features.Get<UpstreamAuthTokenFeature>()?.Token;
        _challengeHandling = true;
        return this;
    }

    /// <summary>
    /// Operate the client in the context of the agent's own approved
    /// <see cref="Agent.Mission"/>. Every outbound request carries the
    /// <c>AAuth-Mission</c> header (<c>{approver, s256}</c>), which the signing
    /// pipeline covers as the <c>aauth-mission</c> component.
    /// </summary>
    /// <remarks>
    /// The challenge handler requests person tokens with the mission's
    /// <c>mission_s256</c>, so resource and auth tokens carry it (#missions). Combine
    /// with <see cref="WithChallengeHandling()"/> / <see cref="WithInteractionHandling()"/>
    /// so the whole resource-access leg (person token + 401 challenge + token
    /// exchange + retry) is handled automatically. This is for the <em>originating</em>
    /// agent that holds its own approved mission; call-chaining intermediaries that
    /// inherit a mission from an upstream token use <see cref="WithCallChaining(string)"/>.
    /// </remarks>
    /// <param name="mission">The agent's own approved mission.</param>
    public AAuthClientBuilder WithMission(Agent.Mission mission)
    {
        ArgumentNullException.ThrowIfNull(mission);
        _mission = mission;
        return this;
    }

    /// <summary>
    /// Configure a self-issued agent token identity. The builder's key is used
    /// for both HTTP signing and token signing. A <see cref="SelfIssuedTokenRefresher"/>
    /// is created internally — no separate <see cref="WithTokenRefresh"/> call is needed.
    /// </summary>
    internal AAuthClientBuilder WithSelfIssuedToken(string issuer, string subject, string? kid = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        _selfIssuedIssuer = issuer;
        _selfIssuedSubject = subject;
        _selfIssuedKid = kid;
        return this;
    }

    /// <summary>
    /// Set the Person Server URL for both the agent token's <c>ps</c> claim and
    /// challenge handling. Calling <see cref="WithChallengeHandling()"/> after this
    /// method uses the stored PS automatically.
    /// </summary>
    public AAuthClientBuilder WithPersonServer(string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _selfIssuedPersonServer = personServer;
        _personServer = personServer;
        return this;
    }

    /// <summary>
    /// Select a refreshed JWT carrier, overriding an earlier scheme selector.
    /// The refresher remains caller-owned. A later explicit Use* selector
    /// disables refresh; resource flow options do not select a scheme.
    /// </summary>
    public AAuthClientBuilder WithTokenRefresh(ITokenRefresher refresher, TimeSpan? refreshThreshold = null)
    {
        ArgumentNullException.ThrowIfNull(refresher);
        _provider = null;
        _ownedTokenRefresherFactory = null;
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
        return WithTokenRefresh(new DelegateTokenRefresher(refreshFunc), refreshThreshold);
    }

    internal AAuthClientBuilder WithOwnedTokenRefresh(Func<AAuthEgressPolicy, ITokenRefresher> factory)
    {
        ClearTokenRefresh();
        _provider = null;
        _ownedTokenRefresherFactory = factory;
        return this;
    }

    private void ClearTokenRefresh()
    {
        _tokenRefresher = null;
        _ownedTokenRefresherFactory = null;
        _selfIssuedIssuer = null;
        _agentToken = null;
        _tokenFactory = null;
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
    /// Enable the resource-managed (two-party) <c>AAuth-Access</c> opaque-token
    /// flow: capture an <c>AAuth-Access</c> response header and replay it as
    /// <c>Authorization: AAuth &lt;token68&gt;</c> on subsequent requests to the
    /// same resource origin, bound to the request signature
    /// (§AAuth-Access Response Header). Typically combined with
    /// <see cref="WithInteractionHandling()"/> so the resource's
    /// <c>202 → interaction → 200 + AAuth-Access</c> handshake is driven
    /// automatically.
    /// </summary>
    /// <param name="store">
    /// Optional per-origin token store. Defaults to a new
    /// <see cref="InMemoryAAuthAccessStore"/>. Supply a shared store for a
    /// multi-instance agent.
    /// </param>
    public AAuthClientBuilder WithResourceManagedAccess(IAAuthAccessStore? store = null)
    {
        _resourceManagedAccess = true;
        _accessStore = store;
        return this;
    }

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpClient Build() => AAuthHttpTransport.AttachPolicy(new HttpClient(BuildHandler()),
        _egressPolicy, _transportContract ?? AAuthTransportContract.EnforcesEgressPolicy);

    /// <summary>
    /// Build a governance client (mission / permission / audit / interaction) that
    /// signs every request with the configured agent JWT. Accepts a held token,
    /// a refresher, or enrolled/self-issued provisioning configuration.
    /// The returned facade owns its internally created clients and must be disposed.
    /// The client is wired from the same signed exchange channel as the token-exchange
    /// pipeline in <see cref="BuildHandler"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public AAuthGovernanceClient BuildGovernance()
        => BuildGovernance(defaultOptions: null);

    /// <summary>
    /// Build a governance client bound to the Person Server configured via
    /// <see cref="WithPersonServer"/>, with default deferred-handling options. The
    /// bound client exposes <see cref="AAuthGovernanceClient.ProposeMissionAsync"/>
    /// which returns a <see cref="Agent.Governance.MissionSession"/> that auto-threads
    /// the mission claim and PS into subsequent calls. Requires an explicit signing
    /// mode and a configured Person Server.
    /// </summary>
    /// <param name="defaultOptions">Default governance options applied when a call omits its own.</param>
    /// <exception cref="InvalidOperationException">No signing mode or no Person Server was configured.</exception>
    public AAuthGovernanceClient BuildGovernance(Agent.Governance.GovernanceOptions? defaultOptions)
    {
        if (_provider is not JwtSignatureKeyProvider && _tokenRefresher is null
            && _ownedTokenRefresherFactory is null && _selfIssuedIssuer is null)
            throw new InvalidOperationException("BuildGovernance requires an agent JWT source. Use UseJwt, Enrolled, SelfIssuing, or WithTokenRefresh.");
        if (string.IsNullOrEmpty(_personServer))
        {
            throw new InvalidOperationException(
                "BuildGovernance requires a Person Server. Configure one via WithPersonServer(...).");
        }
        var agentBuilder = new AAuthClientBuilder(_key)
        {
            _provider = _provider, _agentToken = _agentToken, _tokenFactory = _tokenFactory,
            _tokenRefresher = _tokenRefresher, _ownedTokenRefresherFactory = _ownedTokenRefresherFactory,
            _refreshThreshold = _refreshThreshold, _selfIssuedIssuer = _selfIssuedIssuer,
            _selfIssuedSubject = _selfIssuedSubject, _selfIssuedKid = _selfIssuedKid,
            _selfIssuedPersonServer = _selfIssuedPersonServer, _egressPolicy = _egressPolicy,
            _innerHandler = _innerHandler, _transportContract = _transportContract,
            _capabilities = _capabilities, _onSignatureBase = _onSignatureBase,
        };
        var signed = agentBuilder.Build();
        signed.Timeout = Timeout.InfiniteTimeSpan;
        try
        {
            var metadata = new MetadataClient(policy: _egressPolicy);
            return new AAuthGovernanceClient(signed, metadata, _personServer, defaultOptions, ownsClients: true);
        }
        catch
        {
            signed.Dispose();
            throw;
        }
    }

    // Build a signed HttpClient (pinned to the agent identity) plus a metadata
    // client — the channel used for token exchange and governance calls. The long
    // (infinite) timeout lets deferred long-polling (Prefer: wait=N) run past the
    // default 100s; DeferredPollerOptions.MaxTotalWait enforces the real budget.
    private (HttpClient Signed, MetadataClient Metadata) BuildSignedChannel(
        ISignatureKeyProvider provider, HttpMessageHandler innerHandler)
    {
        var signer = new AAuthSigningHandler(_key, provider)
        {
            InnerHandler = innerHandler,
        };
        var signed = new HttpClient(signer)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        AAuthHttpTransport.AttachPolicy(signed, _egressPolicy, _transportContract ?? AAuthTransportContract.EnforcesEgressPolicy);
        var metadata = new MetadataClient(policy: _egressPolicy);
        return (signed, metadata);
    }

    /// <summary>
    /// Build the configured handler pipeline without wrapping it in an <see cref="HttpClient"/>.
    /// Useful for DI registration via <c>ConfigurePrimaryHttpMessageHandler</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpMessageHandler BuildHandler()
    {
        var owned = new List<IDisposable>();
        HttpMessageHandler? partial = null;
        try
        {
            var handler = BuildHandlerCore(owned, ref partial);
            return owned.Count == 0 ? handler : new OwnedPipelineHandler(handler, owned);
        }
        catch
        {
            partial?.Dispose();
            foreach (var resource in owned) resource.Dispose();
            throw;
        }
    }

    private HttpMessageHandler BuildHandlerCore(List<IDisposable> owned, ref HttpMessageHandler? partial)
    {
        var tokenRefresher = _tokenRefresher;
        if (_ownedTokenRefresherFactory is not null)
        {
            var refresher = _ownedTokenRefresherFactory(_egressPolicy);
            if (refresher is IDisposable disposable) owned.Add(disposable);
            tokenRefresher = refresher;
        }
        // Materialize self-issued token refresher if WithSelfIssuedToken was called.
        if (_selfIssuedIssuer is not null && tokenRefresher is null)
        {
            tokenRefresher = new SelfIssuedTokenRefresher(
                _key,
                _selfIssuedIssuer,
                _selfIssuedSubject!,
                _selfIssuedKid ?? _key.ComputeJwkThumbprint(),
                _selfIssuedPersonServer, egressPolicy: _egressPolicy);
        }

        if (_provider is null && tokenRefresher is null)
            throw new InvalidOperationException(
                "A signature scheme or token source must be configured. Use a Use* scheme selector, Enrolled, SelfIssuing, or WithTokenRefresh before Build().");

        if (!_challengeHandling)
        {
            // When WithTokenRefresh is configured but no explicit provider,
            // create a JWT signing pipeline with lazy token acquisition.
            if (_provider is null && tokenRefresher is not null)
                return WithMissionHeader(BuildRefreshOnlyHandler(tokenRefresher, ref partial));

            // Simple signing-only pipeline (possibly with interaction handling).
            var handler = new AAuthSigningHandler(_key, _provider!)
            {
                InnerHandler = CreateTransport(),
                Capabilities = _interactionHandling ? MergeCapabilities("interaction") : _capabilities,
                OnSignatureBase = _onSignatureBase,
            };
            partial = handler;

            // Resource-managed access handler sits just above the signer so the
            // Authorization: AAuth header it sets is covered by the signature.
            var signed = WrapWithAccessHandler(handler);

            if (!_interactionHandling)
                return WithMissionHeader(signed);

            // Wrap with interaction handler
            var interactionOpts = new InteractionHandlingOptions();
            _interactionOptionsConfigure?.Invoke(interactionOpts);
            var interactionHandler = new InteractionHandler(
                interactionOpts.OnInteractionRequired,
                interactionOpts.OnApprovalPending,
                interactionOpts.PollingTimeout,
                interactionOpts.DefaultPollInterval,
                interactionOpts.MinPollInterval,
                interactionOpts.PreferWaitSeconds,
                interactionOpts.OnPoll)
            {
                EgressPolicy = _egressPolicy,
                TransportContract = _transportContract ?? AAuthTransportContract.EnforcesEgressPolicy,
                InnerHandler = signed,
            };
            return WithMissionHeader(interactionHandler);
        }

        // --- Challenge-handling pipeline ---
        var agentToken = ResolveAgentToken(tokenRefresher is not null);
        var personServer = _upstreamTokenProvider is not null
            ? ResolvePersonServerOptional(agentToken)
            : ResolvePersonServer(agentToken);

        var challengeOptions = new ChallengeHandlingOptions();
        _challengeOptionsConfigure?.Invoke(challengeOptions);

        // Two holders keep the agent token and the exchanged carrier separate. The
        // agent token (kept fresh by the refresh handler below) is what a resource
        // request presents until a carrier is obtained AND what the PS token-exchange is
        // ALWAYS signed with (§Agent Token Request — the PS rejects a non-agent carrier).
        // The carrier holder holds auth tokens obtained via challenge; it never leaks into
        // the exchange, so step-up challenges stay agent-signed by construction.
        var agentTokenHolder = agentToken is not null
            ? new AAuthTokenHolder(agentToken)
            : new AAuthTokenHolder();
        var carrierHolder = new AAuthTokenHolder();

        // Resource requests present the carrier once one is obtained, else the (fresh)
        // agent token.
        var resourceProvider = new JwtSignatureKeyProvider(
            request => carrierHolder.SelectForRequest(request, agentTokenHolder.Current, _key.ComputeJwkThumbprint()));

        // Outer signing handler (signs requests to resources).
        var outerSigner = new AAuthSigningHandler(_key, resourceProvider)
        {
            InnerHandler = CreateTransport(),
            Capabilities = _interactionHandling
                ? MergeCapabilities("auth-token", "interaction")
                : MergeCapabilities("auth-token"),
            OnSignatureBase = _onSignatureBase,
        };
        partial = outerSigner;

        // Exchange pipeline: always agent-signed — a key provider (HWK/JWKS-URI/JktJwt)
        // or the dedicated agent-token channel, never the mutable carrier holder.
        var exchangeProvider = _tokenFactory is not null || _provider is null
            ? new JwtSignatureKeyProvider(() => agentTokenHolder.Current) : _provider;
        var (exchangeHttpClient, metadata) = BuildSignedChannel(exchangeProvider, AAuthHttpTransport.CreateHandler(_egressPolicy));
        owned.Add(exchangeHttpClient);
        owned.Add(metadata);
        var exchangeClient = new TokenExchangeClient(exchangeHttpClient, metadata);
        var jwks = new JwksClient(policy: _egressPolicy);
        owned.Add(jwks);

        var pollerOptions = new DeferredPollerOptions
        {
            MaxTotalWait = challengeOptions.PollingTimeout,
            DefaultPollInterval = challengeOptions.DefaultPollInterval,
            PreferWaitSeconds = challengeOptions.PreferWaitSeconds,
            MinPollInterval = challengeOptions.MinPollInterval,
            OnPoll = challengeOptions.OnPoll,
        };

        // Challenge handler sits above the outer signer.
        var challengeHandler = new ChallengeHandler(
            exchangeClient, carrierHolder, new Tokens.TokenVerifier { EgressPolicy = _egressPolicy }, metadata, jwks, personServer,
            challengeOptions.OnInteractionRequired, pollerOptions,
            _upstreamTokenProvider)
        {
            InnerHandler = WrapWithAccessHandler(outerSigner),
            Capabilities = challengeOptions.Capabilities is { } caps
                ? new System.Collections.Generic.List<string>(caps)
                : null,
            Prompt = challengeOptions.Prompt,
            AdditionalSignatureComponents = challengeOptions.AdditionalSignatureComponents,
            OnClarificationRequired = challengeOptions.OnClarificationRequired,
            MaxClarificationRounds = challengeOptions.MaxClarificationRounds,
            PersonServerProvider = _personServer is null ? () => ResolvePersonServer(agentTokenHolder.Current) : null,
        };

        // If token refresh is configured, insert it above the challenge handler.
        HttpMessageHandler topHandler = challengeHandler;
        partial = topHandler;
        if (tokenRefresher is not null)
        {
            var signingKeyThumbprint = _key.ComputeJwkThumbprint();
            var refreshHandler = new TokenRefreshHandler(agentTokenHolder, tokenRefresher, signingKeyThumbprint, _refreshThreshold)
            {
                InnerHandler = challengeHandler,
            };
            topHandler = refreshHandler;
            partial = topHandler;
        }

        if (_tokenFactory is not null)
        {
            topHandler = new AgentTokenSourceHandler(_tokenFactory, agentTokenHolder, agentToken) { InnerHandler = topHandler };
            partial = topHandler;
        }

        // If interaction handling is configured, insert it at the top.
        if (_interactionHandling)
        {
            var interactionOpts = new InteractionHandlingOptions();
            _interactionOptionsConfigure?.Invoke(interactionOpts);
            var interactionHandler = new InteractionHandler(
                interactionOpts.OnInteractionRequired,
                interactionOpts.OnApprovalPending,
                interactionOpts.PollingTimeout,
                interactionOpts.DefaultPollInterval,
                interactionOpts.MinPollInterval,
                interactionOpts.PreferWaitSeconds,
                interactionOpts.OnPoll)
            {
                EgressPolicy = _egressPolicy,
                TransportContract = _transportContract ?? AAuthTransportContract.EnforcesEgressPolicy,
                InnerHandler = topHandler,
            };
            topHandler = interactionHandler;
            partial = topHandler;
        }

        // If call-chaining is configured, add mission forwarding at the top.
        // Per §Call Chaining, intermediaries in a mission context MUST include
        // AAuth-Mission on downstream requests.
        if (_upstreamTokenProvider is not null)
        {
            var missionHandler = new MissionForwardingHandler(_upstreamTokenProvider)
            {
                InnerHandler = topHandler,
            };
            topHandler = missionHandler;
        }

        return WithMissionHeader(topHandler);
    }

    // Wrap a pipeline with the originating-agent mission header handler when a
    // mission was configured via WithMission(...). Sits at the very top so the
    // AAuth-Mission header is present before the request is signed; the signing
    // handler beneath then covers it as the `aauth-mission` component (§Mission
    // Context at Resources). Skipped under call-chaining, where
    // MissionForwardingHandler already emits the header from the upstream token.
    private HttpMessageHandler WithMissionHeader(HttpMessageHandler inner)
    {
        if (_mission is null || _upstreamTokenProvider is not null)
            return inner;
        return new MissionHeaderHandler(_mission) { InnerHandler = inner };
    }

    // Wrap a signing handler with the resource-managed AAuth-Access handler when
    // WithResourceManagedAccess(...) was called. It sits directly above the signer
    // (inner of interaction/challenge) so the Authorization: AAuth header it sets
    // is present when the signer covers `authorization`.
    private HttpMessageHandler WrapWithAccessHandler(HttpMessageHandler signer)
    {
        if (!_resourceManagedAccess)
            return signer;
        return new AAuthAccessHandler(_accessStore ?? new InMemoryAAuthAccessStore(), _key.ComputeJwkThumbprint())
        {
            InnerHandler = signer,
        };
    }

    private HttpMessageHandler BuildRefreshOnlyHandler(ITokenRefresher refresher, ref HttpMessageHandler? partial)
    {
        var holder = _agentToken is not null ? new AAuthTokenHolder(_agentToken) : new AAuthTokenHolder();
        var provider = new JwtSignatureKeyProvider(() => holder.Current);
        var signingKeyThumbprint = _key.ComputeJwkThumbprint();

        var signingHandler = new AAuthSigningHandler(_key, provider)
        {
            InnerHandler = CreateTransport(),
            Capabilities = _interactionHandling ? MergeCapabilities("interaction") : _capabilities,
            OnSignatureBase = _onSignatureBase,
        };
        partial = signingHandler;

        var refreshHandler = new TokenRefreshHandler(holder, refresher, signingKeyThumbprint, _refreshThreshold)
        {
            InnerHandler = WrapWithAccessHandler(signingHandler),
        };
        partial = refreshHandler;

        HttpMessageHandler topHandler = refreshHandler;
        if (_tokenFactory is not null)
        {
            topHandler = new AgentTokenSourceHandler(_tokenFactory, holder, _agentToken) { InnerHandler = topHandler };
            partial = topHandler;
        }

        if (!_interactionHandling)
            return topHandler;

        var opts = new InteractionHandlingOptions();
        _interactionOptionsConfigure?.Invoke(opts);
        return new InteractionHandler(
            opts.OnInteractionRequired,
            opts.OnApprovalPending,
            opts.PollingTimeout,
            opts.DefaultPollInterval,
            opts.MinPollInterval,
            opts.PreferWaitSeconds,
            opts.OnPoll)
        {
            EgressPolicy = _egressPolicy,
            TransportContract = _transportContract ?? AAuthTransportContract.EnforcesEgressPolicy,
            InnerHandler = topHandler,
        };
    }

    private string? ResolveAgentToken(bool canRefresh)
    {
        if (_agentToken is not null)
            return _agentToken;
        if (_tokenFactory is not null)
            return _tokenFactory();

        // Lazy acquisition: no token provided, but WithTokenRefresh will fetch one
        // on the first request. Return null to signal the holder should start empty.
        if (canRefresh)
            return null;

        throw new InvalidOperationException(
            "WithChallengeHandling() requires a token source. " +
            "Configure WithTokenRefresh() for lazy token acquisition.");
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

    private string? ResolvePersonServerOptional(string? agentToken)
    {
        if (_personServer is not null)
            return _personServer;

        if (agentToken is null)
            return null;

        // Try the 'ps' claim but don't throw — upstream token routing will handle it.
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(agentToken);
        return (string?)payload["ps"];
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
