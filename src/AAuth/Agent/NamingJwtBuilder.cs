using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// Builds a self-issued <c>jkt-jwt</c> delegation JWT per
/// <c>draft-hardt-httpbis-signature-key-05</c> §3.4. The durable (enclave) key
/// signs the JWT and embeds its own public key in the header; the JWT delegates
/// HTTP-signing authority to an ephemeral key named via the <c>cnf.jwk</c> claim.
/// The issuer is the durable key's own JWK Thumbprint URI, so verification is
/// self-anchored (no external issuer lookup).
/// </summary>
public static class NamingJwtBuilder
{
    /// <summary>
    /// Create a <c>jkt-s256+jwt</c> delegation JWT signed by
    /// <paramref name="durableKey"/> that delegates to <paramref name="ephemeralKey"/>.
    /// </summary>
    /// <param name="durableKey">The agent's durable enrollment key (signs this JWT; its public half is embedded in the header <c>jwk</c>).</param>
    /// <param name="ephemeralKey">The fresh ephemeral key whose public half is embedded as <c>cnf.jwk</c>.</param>
    public static string Build(IAAuthKey durableKey, IAAuthKey ephemeralKey)
    {
        ArgumentNullException.ThrowIfNull(durableKey);
        ArgumentNullException.ThrowIfNull(ephemeralKey);

        var now = DateTimeOffset.UtcNow;

        var header = new JsonObject
        {
            ["alg"] = durableKey.Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = durableKey.ToPublicJwk(),
        };

        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + durableKey.ComputeJwkThumbprint(),
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
