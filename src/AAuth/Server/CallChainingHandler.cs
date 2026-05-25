using System;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.HttpSig;

namespace AAuth.Server;

/// <summary>
/// <see cref="DelegatingHandler"/> that enables a resource to act as an
/// agent for downstream resources (call-chaining). Extracts the upstream
/// auth token from the current request context and exchanges it (with
/// <c>upstream_token</c>) at the appropriate downstream PS/AS to obtain
/// a chained auth token.
/// </summary>
/// <remarks>
/// <para>
/// Routing logic (per spec §Call Chaining):
/// <list type="bullet">
/// <item><c>mission.approver</c> present → PS at approver URL</item>
/// <item>No mission, <c>iss</c> is PS (three-party) → PS at <c>iss</c></item>
/// <item>No mission, <c>iss</c> is AS (four-party) → AS at <c>iss</c></item>
/// </list>
/// </para>
/// </remarks>
public sealed class CallChainingHandler
{
    private readonly TokenExchangeClient _exchangeClient;
    private readonly CallChainingOptions _options;

    /// <summary>Create the call-chaining handler.</summary>
    /// <param name="exchangeClient">Exchange client configured with the resource's agent identity.</param>
    /// <param name="options">Call-chaining configuration.</param>
    public CallChainingHandler(TokenExchangeClient exchangeClient, CallChainingOptions options)
    {
        ArgumentNullException.ThrowIfNull(exchangeClient);
        ArgumentNullException.ThrowIfNull(options);
        _exchangeClient = exchangeClient;
        _options = options;
    }

    /// <summary>
    /// Exchange the <paramref name="resourceToken"/> at the downstream PS/AS,
    /// including the <paramref name="upstreamAuthToken"/> to preserve the
    /// delegation chain.
    /// </summary>
    /// <param name="upstreamAuthToken">
    /// The auth token received by this resource from its caller. Included as
    /// <c>upstream_token</c> in the POST body so the downstream PS/AS can
    /// construct a nested <c>act</c> chain.
    /// </param>
    /// <param name="resourceToken">
    /// The resource token issued by the downstream resource's challenge.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The chained auth token for the downstream resource.</returns>
    public async Task<string> ExchangeForDownstreamAsync(
        string upstreamAuthToken,
        string resourceToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);

        // Determine the downstream PS/AS endpoint from the upstream auth token.
        var targetServer = ResolveDownstreamServer(upstreamAuthToken);

        return await _exchangeClient.ExchangeAsync(
            targetServer,
            resourceToken,
            onInteractionRequired: null,
            pollerOptions: null,
            upstreamToken: upstreamAuthToken,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Determine which PS/AS to send the downstream token request to,
    /// based on the upstream auth token's claims.
    /// </summary>
    internal static string ResolveDownstreamServer(string upstreamAuthToken)
    {
        // Decode the upstream auth token payload (no verification needed here —
        // it was already verified by the resource's verification middleware).
        var segments = upstreamAuthToken.Split('.');
        if (segments.Length != 3)
            throw new InvalidOperationException("upstream_token is not a valid JWT.");

        JsonObject payload;
        try
        {
            var payloadJson = System.Text.Encoding.UTF8.GetString(
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]));
            payload = JsonNode.Parse(payloadJson) as JsonObject
                ?? throw new InvalidOperationException("upstream_token payload is not a JSON object.");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException("Failed to decode upstream_token payload.", ex);
        }

        // Route 1: mission.approver present → PS at approver URL.
        if (payload["mission"] is JsonObject mission)
        {
            var approver = (string?)mission["approver"];
            if (!string.IsNullOrEmpty(approver) && AAuthUrl.IsHttpsOrLoopback(approver))
            {
                return approver;
            }
        }

        // Route 2/3: Use iss (PS or AS — the exchange client resolves the
        // correct metadata document based on the server's discovery).
        var iss = (string?)payload["iss"]
            ?? throw new InvalidOperationException("upstream_token is missing 'iss' claim.");

        if (!AAuthUrl.IsHttpsOrLoopback(iss))
            throw new InvalidOperationException(
                $"upstream_token 'iss' must be an absolute https:// URL (or http://localhost): {iss}");

        return iss;
    }
}
