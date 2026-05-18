using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Agent;

/// <summary>
/// Exchanges a resource token at the agent's Person Server for an auth
/// token (three-party autonomous flow). Returns the auth-token JWT on
/// success, or surfaces the PS response body / status to the caller.
/// </summary>
/// <remarks>
/// The HTTP POST to the PS's <c>token_endpoint</c> MUST be signed with the
/// agent's key (RFC 9421) and carry the agent's agent token in
/// <c>Signature-Key</c>. The caller is expected to supply an
/// <see cref="HttpClient"/> wrapped in an
/// <see cref="HttpSig.AAuthSigningHandler"/> configured with the agent
/// token, just like any other outbound AAuth request.
/// </remarks>
public sealed class TokenExchangeClient
{
    private readonly HttpClient _signedClient;
    private readonly MetadataClient _metadata;

    /// <summary>Create the exchange client.</summary>
    /// <param name="signedClient">HttpClient already wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS <c>token_endpoint</c>.</param>
    public TokenExchangeClient(HttpClient signedClient, MetadataClient metadata)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        _signedClient = signedClient;
        _metadata = metadata;
    }

    /// <summary>
    /// Submit <paramref name="resourceToken"/> to the PS at
    /// <paramref name="personServer"/> and return the auth token.
    /// </summary>
    /// <returns>The compact <c>aa-auth+jwt</c>.</returns>
    public async Task<string> ExchangeAsync(
        string personServer,
        string resourceToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);

        var metadataUrl = MetadataClient.BuildUrl(personServer, "aauth-person.json");
        var doc = await _metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        var tokenEndpoint = (string?)doc["token_endpoint"]
            ?? throw new InvalidOperationException(
                $"Person Server metadata at {metadataUrl} is missing 'token_endpoint'.");

        // A malicious or compromised PS metadata document could otherwise
        // redirect the signed exchange request to an arbitrary URL (SSRF
        // pivot for the agent) or downgrade it to plain http. Require the
        // same https-or-loopback policy used elsewhere, and pin the
        // endpoint to the same origin as the configured PS so a metadata
        // compromise can't divert the signed exchange off-host.
        if (!AAuthUrl.IsHttpsOrLoopback(tokenEndpoint)
            || !Uri.TryCreate(tokenEndpoint, UriKind.Absolute, out var tokenEndpointUri))
        {
            throw new InvalidOperationException(
                $"Person Server 'token_endpoint' must be an absolute https:// URL (or http://localhost): {tokenEndpoint}");
        }
        if (!Uri.TryCreate(personServer, UriKind.Absolute, out var psUri)
            || !string.Equals(
                tokenEndpointUri.GetLeftPart(UriPartial.Authority),
                psUri.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Person Server 'token_endpoint' must share an origin with {personServer}: {tokenEndpoint}");
        }

        var body = new JsonObject { ["resource_token"] = resourceToken };
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpointUri)
        {
            Content = JsonContent.Create(body),
        };
        using var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Token exchange failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{responseBody}");
        }

        var json = JsonNode.Parse(responseBody) as JsonObject
            ?? throw new InvalidOperationException("Token exchange response was not a JSON object.");
        return (string?)json["auth_token"]
            ?? throw new InvalidOperationException("Token exchange response did not include 'auth_token'.");
    }
}
