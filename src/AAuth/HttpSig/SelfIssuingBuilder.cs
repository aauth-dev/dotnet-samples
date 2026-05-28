using System;
using System.Net.Http;
using AAuth.Crypto;
using AAuth.Server;
using Microsoft.AspNetCore.Http;

namespace AAuth.HttpSig;

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
    public AAuthClientBuilder WithInnerHandler(HttpMessageHandler handler)
    {
        return ToBuilder().WithInnerHandler(handler);
    }

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    public HttpClient Build() => ToBuilder().Build();

    /// <summary>Build the configured handler pipeline.</summary>
    public HttpMessageHandler BuildHandler() => ToBuilder().BuildHandler();

    private AAuthClientBuilder ToBuilder()
    {
        if (_issuer is null || _subject is null)
            throw new InvalidOperationException(
                "As(issuer, subject) must be called before building.");
        return new AAuthClientBuilder(_key).WithSelfIssuedToken(_issuer, _subject, _kid);
    }
}
