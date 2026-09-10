using System;
using System.Net.Http;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Http;

namespace AAuth;

/// <summary>
/// Fluent sub-builder for configuring a self-issued agent identity.
/// Returned by <see cref="AAuthClientBuilder.SelfIssuing(IAAuthKey)"/>.
/// </summary>
/// <example>
/// <code>
/// using var client = AAuthClientBuilder.SelfIssuing(key)
///     .As(issuer, subject)
///     .WithPersonServer(ps)
///     .WithChallengeHandling()
///     .Build();
/// </code>
/// </example>
public sealed class SelfIssuingBuilder
{
    private readonly IAAuthKey _key;
    private string? _issuer;
    private string? _subject;
    private string? _kid;
    private AAuth.Discovery.AAuthEgressPolicy _egressPolicy = AAuth.Discovery.AAuthEgressPolicy.Production;

    public SelfIssuingBuilder WithEgressPolicy(AAuth.Discovery.AAuthEgressPolicy policy)
    {
        _egressPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
        return this;
    }

    public SelfIssuingBuilder WithDevelopmentLoopback(params string[] origins) =>
        WithEgressPolicy(AAuth.Discovery.AAuthEgressPolicy.ForDevelopmentLoopback(origins));

    internal SelfIssuingBuilder(IAAuthKey key)
    {
        _key = key;
    }

    /// <summary>
    /// Set the issuer and subject for the self-issued agent token.
    /// </summary>
    /// <param name="issuer">Issuer URL (the service's own HTTPS URL).</param>
    /// <param name="subject">Agent identifier (e.g. <c>aauth:my-service@my-service.example</c>).</param>
    public SelfIssuingBuilder As(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        _issuer = issuer;
        _subject = subject;
        return this;
    }

    /// <summary>
    /// Set a custom key ID for the agent token header. Defaults to the key's JWK thumbprint.
    /// </summary>
    public SelfIssuingBuilder WithKid(string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        _kid = kid;
        return this;
    }

    /// <summary>
    /// Set the Person Server URL for both the agent token's <c>ps</c> claim
    /// and challenge handling.
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

    /// <summary>Enable resource-managed opaque access credentials without a PS/AS exchange.</summary>
    public AAuthClientBuilder WithResourceManagedAccess(Agent.IAAuthAccessStore? store = null) =>
        ToBuilder().WithResourceManagedAccess(store);

    /// <summary>Enable resource interaction handling.</summary>
    public AAuthClientBuilder WithInteractionHandling() => ToBuilder().WithInteractionHandling();

    /// <summary>Configure resource interaction handling.</summary>
    public AAuthClientBuilder WithInteractionHandling(Action<InteractionHandlingOptions> configure) =>
        ToBuilder().WithInteractionHandling(configure);

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
        if (_issuer is null || _subject is null)
            throw new InvalidOperationException(
                "As(issuer, subject) must be called before building.");
        return new AAuthClientBuilder(_key).WithEgressPolicy(_egressPolicy).WithSelfIssuedToken(_issuer, _subject, _kid);
    }
}
