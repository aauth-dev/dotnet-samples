using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// Builds a naming JWT for two-key (<c>jkt-jwt</c>) refresh per the bootstrap spec
/// (§ Two-Key Refresh). The naming JWT is signed by the durable key and names
/// the new ephemeral key via its <c>cnf.jwk</c> claim.
/// </summary>
public static class NamingJwtBuilder
{
    /// <summary>
    /// Create a naming JWT signed by <paramref name="durableKey"/> that delegates
    /// to <paramref name="ephemeralKey"/>.
    /// </summary>
    /// <param name="durableKey">The agent's durable enrollment key (signs this JWT).</param>
    /// <param name="ephemeralKey">The fresh ephemeral key whose public half is embedded as <c>cnf.jwk</c>.</param>
    /// <param name="issuer">AP issuer URL (used as <c>iss</c> so the AP can verify against its own JWKS).</param>
    /// <param name="kid">Key identifier for the JWT header (<c>kid</c>) — the durable key's thumbprint.</param>
    public static string Build(IAAuthKey durableKey, IAAuthKey ephemeralKey, string issuer, string kid)
    {
        var now = DateTimeOffset.UtcNow;

        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.NamingJwt,
            ["kid"] = kid,
        };

        var payload = new JsonObject
        {
            ["iss"] = issuer,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.Add(TimeSpan.FromMinutes(5)).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject
            {
                ["jwk"] = ephemeralKey.ToPublicJwk(),
            },
        };

        return JwtWriter.SignCompact(header, payload, durableKey);
    }
}
