using System;

namespace AAuth.HttpSig;

/// <summary>
/// Produces the <c>jwt</c> Signature-Key carrier. Token purpose (agent, auth or
/// subscribe) and endpoint authorization are independent of the carrier scheme.
/// </summary>
public sealed class JwtSignatureKeyProvider : ISignatureKeyProvider
{
    private readonly Func<string>? _tokenFactory;
    private readonly Func<System.Net.Http.HttpRequestMessage, string>? _requestTokenFactory;
    private readonly string _label;

    public JwtSignatureKeyProvider(Func<string> tokenFactory, string label = "sig")
    {
        ArgumentNullException.ThrowIfNull(tokenFactory);
        _tokenFactory = tokenFactory;
        _label = SignatureKeyHeader.Label(label);
    }

    public JwtSignatureKeyProvider(Func<System.Net.Http.HttpRequestMessage, string> tokenFactory, string label = "sig")
    {
        ArgumentNullException.ThrowIfNull(tokenFactory);
        _requestTokenFactory = tokenFactory;
        _label = SignatureKeyHeader.Label(label);
    }

    public string GetSignatureKeyHeader() => SignatureKeyHeader.FormatJwt(
        _tokenFactory?.Invoke() ?? throw new InvalidOperationException("This provider requires an HTTP request context."), _label);

    public string GetSignatureKeyHeader(System.Net.Http.HttpRequestMessage request)
    {
        var token = _requestTokenFactory is null ? _tokenFactory!() : _requestTokenFactory(request);
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.PresentedToken, token);
        return SignatureKeyHeader.FormatJwt(token, _label);
    }
}
