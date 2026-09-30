using System.Net.Http.Headers;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Events;

public sealed class EventsProtocol
{
    private readonly HttpClient _http;
    private readonly MetadataClient _metadata;
    private readonly JwksClient _jwks;
    private readonly DefaultSignatureKeyResolver _resolver;
    public TokenVerifier TokenVerifier { get; }

    public EventsProtocol(HttpClient http, IEnumerable<ISignatureTokenVerifier> tokenVerifiers,
        TimeProvider? timeProvider = null)
    {
        _http = http;
        var policy = AAuthHttpTransport.GetPolicy(http);
        timeProvider ??= TimeProvider.System;
        TokenVerifier = new TokenVerifier { EgressPolicy = policy, ClockSkew = TimeSpan.Zero,
            TimeProvider = timeProvider };
        _metadata = new MetadataClient(http, timeProvider: timeProvider);
        _jwks = new JwksClient(http, timeProvider: timeProvider);
        _resolver = new DefaultSignatureKeyResolver(_jwks, _metadata, TokenVerifier, tokenVerifiers);
    }

    public async Task<AAuthVerifiedAssertion?> VerifyRequestAsync(HttpContext context, string type,
        string? audience = null)
    {
        context.Features.Set<AAuthVerifiedAssertion>(null);
        try
        {
            foreach (var header in new[] { "Signature-Key", "Signature-Input", "Signature" })
                if (context.Request.Headers[header].Count != 1 || string.IsNullOrWhiteSpace(context.Request.Headers[header][0]))
                    throw new FormatException("Missing or repeated signature header.");
        }
        catch (FormatException)
        {
            context.Response.StatusCode = 400;
            return null;
        }
        if (context.Request.ContentLength > 65536)
        {
            context.Response.StatusCode = 413;
            return null;
        }
        context.Request.EnableBuffering(65536, 65536);
        AAuthVerifiedAssertion? verified = null;
        var middleware = new AAuthVerificationMiddleware(next =>
        {
            var assertion = next.Features.Get<AAuthVerifiedAssertion>();
            if (assertion?.Token.TokenType != type || audience is not null
                && EventsTokens.RequireText(assertion.Token.Payload, "aud") != audience)
                next.Response.StatusCode = 401;
            else verified = assertion;
            return Task.CompletedTask;
        }, new AAuthVerifier { TimeProvider = TokenVerifier.TimeProvider }, _resolver, _metadata, _jwks,
        new AAuthVerificationOptions
        {
            EgressPolicy = TokenVerifier.EgressPolicy, TimeProvider = TokenVerifier.TimeProvider, ClockSkew = TimeSpan.Zero,
            AcceptedSchemes = [type == EventsTokens.EventType ? "self-jwt" : "jwt"],
            RequireBodyCoverage = true
        });
        try { await middleware.InvokeAsync(context).ConfigureAwait(false); }
        catch (IOException) { context.Response.StatusCode = 413; }
        return verified;
    }

    internal static bool HasHttpBody(HttpRequest request) =>
        request.ContentLength > 0
        || request.ContentLength is null
            && (request.ContentType is not null || request.Headers.ContainsKey(Microsoft.Net.Http.Headers.HeaderNames.TransferEncoding));

    public async Task<TokenVerifier.VerifiedToken> VerifyEventAsync(string jwt, string agent,
        CancellationToken cancellationToken = default)
    {
        var info = SignatureKeyParser.ParseAny(SignatureKeyHeader.FormatSelfJwt(jwt));
        var resolution = await _resolver.ResolveAsync(info, cancellationToken).ConfigureAwait(false);
        var token = resolution.VerifiedToken ?? throw new TokenVerificationException("Unverified event.");
        if (token.TokenType != EventsTokens.EventType || EventsTokens.RequireText(token.Payload, "aud") != agent)
            throw new TokenVerificationException("Event type or audience mismatch.");
        return token;
    }

    public async Task<Uri> ResolveEventEndpointAsync(string provider, CancellationToken cancellationToken = default)
    {
        var metadata = await _metadata.FetchAsync(_metadata.GetUrl(provider, EventsTokens.AgentDwk), cancellationToken).ConfigureAwait(false);
        return _metadata.Policy.ValidateUrl(EventsTokens.RequireText(metadata, "event_endpoint"), endpoint: true);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, Uri url, IAAuthSigner key,
        string jwt, bool selfIssued, byte[]? body = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is { Length: > 0 })
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]);
        }
        using var signer = new AAuthSigningHandler(key, selfIssued
            ? new SelfJwtSignatureKeyProvider(() => jwt) : new JwtSignatureKeyProvider(() => jwt), TokenVerifier.TimeProvider);
        await signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
        return await AAuthHttpTransport.SendAsync(_http, request, cancellationToken).ConfigureAwait(false);
    }
}