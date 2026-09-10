using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using System.Net;

namespace AAuth.R3;

/// <summary>Fetches R3 documents/proposals with jwks_uri-signed requests and verifies r3_s256.</summary>
public sealed class R3FetchClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly AAuthEgressPolicy _policy;
    private readonly bool _ownsClient;

    public R3FetchClient(HttpClient http, bool ownsClient = false)
    {
        _policy = AAuthHttpTransport.GetPolicy(http);
        _http = http;
        _ownsClient = ownsClient;
    }

    public static R3FetchClient Create(IAAuthKey signingKey, string identifier, string dwk, string kid,
        HttpMessageHandler? innerHandler = null, AAuthEgressPolicy? policy = null,
        AAuthTransportContract? transportContract = null)
    {
        policy ??= AAuthEgressPolicy.Production;
        policy.ValidateIdentifier(identifier);
        var builder = new AAuthClientBuilder(signingKey).WithEgressPolicy(policy).UseJwksUri(identifier, dwk, kid);
        if (innerHandler is not null) builder.WithInnerHandler(new BorrowedHandler(innerHandler), transportContract);
        return new R3FetchClient(builder.Build(), ownsClient: true);
    }

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }

    public async Task<byte[]> FetchAndVerifyAsync(
        string r3Uri,
        string r3S256,
        string resourceIssuer,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(r3S256);
        var uri = ValidateFetchTarget(r3Uri, resourceIssuer, _policy);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await AAuthHttpTransport.SendAsync(_http, request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        R3Hash.Verify(bytes, r3S256);
        return bytes;
    }

    public static Uri ValidateFetchTarget(string r3Uri, string resourceIssuer, AAuthEgressPolicy? policy = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(resourceIssuer);
        policy ??= AAuthEgressPolicy.Production;
        policy.ValidateIdentifier(resourceIssuer);
        var uri = policy.ValidateUrl(r3Uri);
        if (uri.GetLeftPart(UriPartial.Authority) != resourceIssuer)
        {
            throw new InvalidOperationException("r3_uri origin must match the verified resource issuer.");
        }
        return uri;
    }

    internal static bool IsHttpOrHttps(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        || string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

    private sealed class BorrowedHandler(HttpMessageHandler handler) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _invoker = new(handler, disposeHandler: false);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing) _invoker.Dispose();
            base.Dispose(disposing);
        }
    }
}
