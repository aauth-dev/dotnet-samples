using System;
using System.Net.Http;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Http;

namespace AAuth;

/// <summary>
/// Fluent sub-builder for configuring an AP-enrolled agent client.
/// Returned by <see cref="AAuthClientBuilder.Enrolled(IAAuthKey)"/>.
/// </summary>
/// <example>
/// <code>
/// using var client = AAuthClientBuilder.Enrolled(key)
///     .RefreshingFrom(refreshEndpoint, localKeyHandle)
///     .WithKeyStore(keyStore)
///     .WithPersonServer(ps)
///     .WithChallengeHandling()
///     .Build();
/// </code>
/// </example>
public sealed class EnrolledBuilder
{
    private readonly IAAuthKey _key;
    private string? _refreshEndpoint;
    private string? _localKeyHandle;
    private IKeyStore? _keyStore;
    private RefreshMode _refreshMode = RefreshMode.SingleKey;
    private AAuth.Discovery.AAuthEgressPolicy _egressPolicy = AAuth.Discovery.AAuthEgressPolicy.Production;

    public EnrolledBuilder WithEgressPolicy(AAuth.Discovery.AAuthEgressPolicy policy)
    {
        _egressPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
        return this;
    }

    public EnrolledBuilder WithDevelopmentLoopback(params string[] origins) =>
        WithEgressPolicy(AAuth.Discovery.AAuthEgressPolicy.ForDevelopmentLoopback(origins));

    internal EnrolledBuilder(IAAuthKey key)
    {
        _key = key;
    }

    /// <summary>
    /// Configure the AP refresh endpoint and the local key handle used to sign refresh requests.
    /// </summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    /// <param name="localKeyHandle">Agent-local <see cref="IKeyStore"/> handle for the durable signing key.</param>
    public EnrolledBuilder RefreshingFrom(string refreshEndpoint, string localKeyHandle)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);
        _refreshEndpoint = refreshEndpoint;
        _localKeyHandle = localKeyHandle;
        return this;
    }

    /// <summary>
    /// Use a custom <see cref="IKeyStore"/> instead of <see cref="FileKeyStore.Default()"/>.
    /// </summary>
    public EnrolledBuilder WithKeyStore(IKeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        _keyStore = keyStore;
        return this;
    }

    /// <summary>
    /// Set the refresh mode. Default is <see cref="RefreshMode.SingleKey"/>.
    /// </summary>
    /// <remarks>TwoKey is rejected when building this fixed-key pipeline. Use AgentProviderClient.RefreshTwoKeyAsync and coordinate the returned token/key pair explicitly.</remarks>
    /// <param name="mode">Refresh mode to use.</param>
    public EnrolledBuilder WithRefreshMode(RefreshMode mode)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        _refreshMode = mode;
        return this;
    }

    /// <summary>
    /// Set the Person Server URL for challenge handling.
    /// </summary>
    public AAuthClientBuilder WithPersonServer(string personServer)
    {
        return ToBuilder().WithPersonServer(personServer);
    }

    /// <summary>Enable automatic 401 challenge handling (PS resolved from token).</summary>
    public AAuthClientBuilder WithChallengeHandling()
    {
        return ToBuilder().WithChallengeHandling();
    }

    /// <summary>Enable automatic 401 challenge handling with an explicit Person Server URL.</summary>
    public AAuthClientBuilder WithChallengeHandling(string personServer)
    {
        return ToBuilder().WithChallengeHandling(personServer);
    }

    /// <summary>Enable automatic 401 challenge handling with options.</summary>
    public AAuthClientBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    {
        return ToBuilder().WithChallengeHandling(configure);
    }

    /// <summary>Enable interaction handling for deferred consent flows.</summary>
    public AAuthClientBuilder WithInteractionHandling()
    {
        return ToBuilder().WithInteractionHandling();
    }

    /// <summary>Enable interaction handling with options.</summary>
    public AAuthClientBuilder WithInteractionHandling(Action<InteractionHandlingOptions> configure)
    {
        return ToBuilder().WithInteractionHandling(configure);
    }

    /// <summary>Enable resource-managed opaque access credentials without a PS/AS exchange.</summary>
    public AAuthClientBuilder WithResourceManagedAccess(IAAuthAccessStore? store = null)
    {
        return ToBuilder().WithResourceManagedAccess(store);
    }

    /// <summary>Enable call-chaining with a delegate that provides the upstream auth token.</summary>
    public AAuthClientBuilder WithCallChaining(Func<string?> upstreamTokenProvider)
    {
        return ToBuilder().WithCallChaining(upstreamTokenProvider);
    }

    /// <summary>Enable call-chaining with a fixed upstream auth token.</summary>
    public AAuthClientBuilder WithCallChaining(string upstreamAuthToken)
    {
        return ToBuilder().WithCallChaining(upstreamAuthToken);
    }

    /// <summary>Enable call-chaining from the current HTTP context.</summary>
    public AAuthClientBuilder WithCallChaining(HttpContext httpContext)
    {
        return ToBuilder().WithCallChaining(httpContext);
    }

    /// <summary>Override the inner HTTP handler.</summary>
    public AAuthClientBuilder WithInnerHandler(HttpMessageHandler handler, AAuth.Discovery.AAuthTransportContract? transportContract = null)
    {
        return ToBuilder().WithInnerHandler(handler, transportContract);
    }

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    public HttpClient Build() => ToBuilder().Build();

    /// <summary>Build the configured handler pipeline.</summary>
    public HttpMessageHandler BuildHandler() => ToBuilder().BuildHandler();

    /// <summary>Finish provisioning configuration and select general client options without enabling a flow or making a network call.</summary>
    public AAuthClientBuilder ToBuilder()
    {
        if (_refreshEndpoint is null || _localKeyHandle is null)
            throw new InvalidOperationException(
                "RefreshingFrom(endpoint, keyHandle) must be called before building.");

        if (_refreshMode == RefreshMode.TwoKey)
            throw new InvalidOperationException(
                "Enrolled uses a fixed signing key. Use AgentProviderClient.RefreshTwoKeyAsync and build with its returned EphemeralKey and AgentToken for two-key refresh.");

        var endpoint = _refreshEndpoint;
        var keyHandle = _localKeyHandle;
        var keyStore = _keyStore;

        return new AAuthClientBuilder(_key)
            .WithEgressPolicy(_egressPolicy)
            .WithOwnedTokenRefresh(policy => AgentProviderTokenRefresher.Create(endpoint, keyHandle)
                .WithEgressPolicy(policy)
                .WithKeyStore(keyStore ?? FileKeyStore.Default())
                .Build());
    }
}
