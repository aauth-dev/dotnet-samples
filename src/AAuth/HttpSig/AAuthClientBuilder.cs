using System;
using System.Collections.Generic;
using System.Net.Http;
using AAuth.Crypto;

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
        _provider = new JwtSignatureKeyProvider(tokenFactory);
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

    /// <summary>Build the configured <see cref="HttpClient"/>.</summary>
    /// <exception cref="InvalidOperationException">No signing mode was configured.</exception>
    public HttpClient Build()
    {
        if (_provider is null)
            throw new InvalidOperationException(
                "A signing mode must be configured. Call UseHwk(), UseJwt(), UseJwksUri(), or UseJktJwt() before Build().");

        var handler = new AAuthSigningHandler(_key, _provider)
        {
            InnerHandler = _innerHandler ?? new HttpClientHandler(),
            Capabilities = _capabilities,
            OnSignatureBase = _onSignatureBase,
        };
        return new HttpClient(handler);
    }
}
