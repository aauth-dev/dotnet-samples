using AAuth;
using AAuth.Crypto;

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
        if (innerHandler is not null)
        {
            builder.WithInnerHandler(innerHandler);
        }
        return new R3FetchClient(builder.Build());
    }

    public async Task<byte[]> FetchAndVerifyAsync(string r3Uri, string r3S256, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(r3Uri);
        ArgumentException.ThrowIfNullOrEmpty(r3S256);
        using var response = await _http.GetAsync(r3Uri, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        R3Hash.Verify(bytes, r3S256);
        return bytes;
    }
}
