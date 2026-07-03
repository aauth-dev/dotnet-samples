using AAuth;
using AAuth.Crypto;
using System.Net;

namespace AAuth.R3;

/// <summary>Fetches R3 documents/proposals with jwks_uri-signed requests and verifies r3_s256.</summary>
public sealed class R3FetchClient
{
    private readonly HttpClient _http;

    public R3FetchClient(HttpClient http)
    {
        _http = http;
    }

    public static R3FetchClient Create(IAAuthKey signingKey, string jwksUri, string kid, HttpMessageHandler? innerHandler = null)
    {
        var builder = new AAuthClientBuilder(signingKey).UseJwksUri(jwksUri, kid);
        builder.WithInnerHandler(innerHandler ?? new HttpClientHandler { AllowAutoRedirect = false });
        return new R3FetchClient(builder.Build());
    }

    public async Task<byte[]> FetchAndVerifyAsync(
        string r3Uri,
        string r3S256,
        string resourceIssuer,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(r3S256);
        var uri = ValidateFetchTarget(r3Uri, resourceIssuer);
        using var response = await _http.GetAsync(uri, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        R3Hash.Verify(bytes, r3S256);
        return bytes;
    }

    // SSRF posture: the fetch target is pinned to the SAME ORIGIN as the
    // signature-verified resource issuer (SameOrigin below), so the AS can only
    // ever fetch from the resource whose token it just verified — not an arbitrary
    // internal host — and r3_s256 hash verification blocks any content substitution.
    // The IP-literal private/link-local block is defense-in-depth (loopback allowed
    // for local dev). A DNS name that resolves to a private IP is deliberately NOT
    // pre-resolved here: a resolve-then-connect pre-check is TOCTOU-unsound and would
    // be a one-off vs. the rest of the SDK, which pins by origin + scheme.
    public static Uri ValidateFetchTarget(string r3Uri, string resourceIssuer)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(resourceIssuer);
        if (!Uri.TryCreate(r3Uri, UriKind.Absolute, out var uri) || !IsHttpOrHttps(uri))
        {
            throw new InvalidOperationException("r3_uri must be an absolute http or https URI.");
        }
        if (!Uri.TryCreate(resourceIssuer, UriKind.Absolute, out var issuer) || !SameOrigin(uri, issuer))
        {
            throw new InvalidOperationException("r3_uri origin must match the verified resource issuer.");
        }
        if (IsPrivateOrLinkLocal(uri) && !uri.IsLoopback)
        {
            throw new InvalidOperationException("r3_uri IP-literal host must not be private or link-local.");
        }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !uri.IsLoopback)
        {
            throw new InvalidOperationException("r3_uri must use https unless it targets loopback.");
        }
        return uri;
    }

    internal static bool IsHttpOrHttps(Uri uri) =>
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        || string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static bool IsPrivateOrLinkLocal(Uri uri)
    {
        if (uri.HostNameType != UriHostNameType.IPv4 && uri.HostNameType != UriHostNameType.IPv6)
        {
            return false;
        }
        if (!IPAddress.TryParse(uri.Host, out var address))
        {
            return false;
        }
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal;
        }
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254);
    }
}
