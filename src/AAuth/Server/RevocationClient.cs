using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Server;

public sealed class RevocationClient
{
    private readonly HttpClient _signedHttp;

    public RevocationClient(HttpClient signedHttp)
    {
        ArgumentNullException.ThrowIfNull(signedHttp);
        _ = AAuthHttpTransport.GetPolicy(signedHttp);
        _signedHttp = signedHttp;
    }

    public async Task<HttpStatusCode> RevokeAsync(Uri endpoint, TokenKey token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(token);
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(new { iss = token.Issuer, jti = token.TokenId }),
        };
        using var response = await AAuthHttpTransport.SendAsync(_signedHttp, request, cancellationToken);
        return response.StatusCode;
    }
}