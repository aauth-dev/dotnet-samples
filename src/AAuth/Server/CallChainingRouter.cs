using System;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Server;

/// <summary>
/// Pure-function routing logic for call chaining per §Call Chaining.
/// Determines which PS/AS the intermediary should contact to exchange
/// a downstream resource token, based on the upstream auth token's claims.
/// </summary>
public static class CallChainingRouter
{
    /// <summary>
    /// Resolve the downstream PS/AS server URL from the upstream auth token.
    /// </summary>
    /// <remarks>
    /// <para>Routing priority (per spec):</para>
    /// <list type="number">
    /// <item><c>mission.approver</c> present and valid → PS at approver URL.</item>
    /// <item>No mission → PS/AS at <c>iss</c> claim.</item>
    /// </list>
    /// <para>
    /// Security: if <c>mission.approver</c> is present but invalid (empty,
    /// non-https, non-loopback), the method throws rather than silently
    /// falling through to <c>iss</c>. This prevents a compromised upstream
    /// from re-routing a chained request to a different governance authority.
    /// </para>
    /// </remarks>
    /// <param name="upstreamAuthToken">The verified upstream auth token (compact JWS).</param>
    /// <returns>The target server URL for the downstream token exchange.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the token is malformed, <c>mission.approver</c> is invalid,
    /// or <c>iss</c> is missing/invalid.
    /// </exception>
    public static string ResolveDownstreamServer(string upstreamAuthToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);

        var segments = upstreamAuthToken.Split('.');
        if (segments.Length != 3)
            throw new InvalidOperationException("upstream_token is not a valid JWT (expected 3 segments).");

        JsonObject payload;
        try
        {
            var payloadJson = Encoding.UTF8.GetString(
                Base64UrlEncoder.DecodeBytes(segments[1]));
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

            // Security: mission.approver present but empty → fail-fast.
            if (approver is not null && string.IsNullOrWhiteSpace(approver))
                throw new InvalidOperationException(
                    "upstream_token 'mission.approver' is present but empty. " +
                    "Cannot fall through to 'iss' — this may indicate a compromised upstream.");

            if (!string.IsNullOrEmpty(approver))
            {
                if (!AAuthUrl.IsHttpsOrLoopback(approver))
                    throw new InvalidOperationException(
                        $"upstream_token 'mission.approver' must be an absolute https:// URL " +
                        $"(or http://localhost): {approver}");

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
