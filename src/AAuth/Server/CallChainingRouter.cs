using System;
using System.Text.Json.Nodes;

namespace AAuth.Server;

/// <summary>
/// Pure-function router that determines where to send a downstream
/// token-exchange request when a resource is acting as an agent
/// (call chaining / multi-hop). Encodes the three routing rules from
/// §Call Chaining of the AAuth protocol specification.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><c>mission.approver</c> present → PS at approver URL.</item>
/// <item>No mission, <c>iss</c> is PS (three-party) → PS at <c>iss</c>.</item>
/// <item>No mission, <c>iss</c> is AS (four-party) → AS at <c>iss</c>.</item>
/// </list>
/// <para>
/// This component does not contact the network and does not verify the
/// upstream token's signature — that is performed by the inbound
/// verification middleware before the token reaches this code path. The
/// router only decodes the JWT payload to read its claims.
/// </para>
/// </remarks>
public static class CallChainingRouter
{
    /// <summary>
    /// Determine the PS/AS endpoint URL to send a downstream token
    /// exchange request to, based on the upstream auth token's claims.
    /// </summary>
    /// <param name="upstreamAuthToken">The verified upstream <c>aa-auth+jwt</c>.</param>
    /// <returns>The PS or AS issuer URL to which the exchange request is addressed.</returns>
    /// <exception cref="InvalidOperationException">
    /// The upstream token is malformed, missing <c>iss</c>, or names an
    /// <c>iss</c>/<c>mission.approver</c> that violates the https-or-loopback
    /// policy.
    /// </exception>
    public static string ResolveDownstreamServer(string upstreamAuthToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);

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
