using System;
using System.Text.Json.Nodes;

namespace AAuth.Server.CallChaining;

/// <summary>
/// Pure-function routing logic for call chaining per §Call Chaining. The
/// intermediary routes downstream token requests to the person server the
/// upstream token names: the <c>iss</c> of a person token, the <c>ps</c> of an
/// auth token. The <c>ps</c> in the intermediary's own agent token is not used.
/// </summary>
public static class CallChainingRouter
{
    /// <summary>Resolve the downstream person server from the upstream token.</summary>
    /// <param name="upstreamToken">The upstream person or auth token (compact JWS).</param>
    /// <param name="policy">Egress policy for the URL check.</param>
    /// <returns>The person server URL the downstream requests go to.</returns>
    /// <exception cref="InvalidOperationException">
    /// The token is malformed, has an unexpected <c>typ</c>, or names no valid person server.
    /// </exception>
    public static string ResolveDownstreamServer(string upstreamToken, AAuth.Discovery.AAuthEgressPolicy? policy = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamToken);

        var segments = upstreamToken.Split('.');
        if (segments.Length != 3)
            throw new InvalidOperationException("upstream_token is not a valid JWT (expected 3 segments).");

        JsonObject header, payload;
        try
        {
            header = AAuth.Tokens.TokenVerifier.DecodeJsonSegment(segments[0], "header");
            payload = AAuth.Tokens.TokenVerifier.DecodeJsonSegment(segments[1], "payload");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to decode upstream_token.", ex);
        }

        var personServer = (string?)header["typ"] switch
        {
            AAuth.Tokens.PersonTokenBuilder.TokenType => (string?)payload["iss"],
            AAuth.Tokens.AuthTokenBuilder.TokenType => (string?)payload["ps"],
            _ => throw new InvalidOperationException("upstream_token must be a person token or an auth token."),
        };
        if (string.IsNullOrEmpty(personServer) || !AAuthUrl.IsHttpsOrLoopback(personServer, policy))
            throw new InvalidOperationException(
                $"upstream_token must name an absolute https:// person server (or http://localhost): {personServer}");
        return personServer;
    }
}
