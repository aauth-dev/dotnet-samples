using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Shared JWT compact-serialization helper for the AAuth token builders.
/// Centralizes the header/payload/signature assembly that
/// <see cref="AgentTokenBuilder"/>, <see cref="ResourceTokenBuilder"/>, and
/// <see cref="AuthTokenBuilder"/> all need.
/// </summary>
internal static class JwtWriter
{
    /// <summary>Serialize, sign, and return the compact JWS string.</summary>
    public static async ValueTask<string> SignCompactAsync(JsonObject header, JsonObject payload, IAAuthSigner key,
        CancellationToken cancellationToken = default)
    {
        var headerBytes = Encoding.UTF8.GetBytes(header.ToJsonString());
        var payloadBytes = Encoding.UTF8.GetBytes(payload.ToJsonString());

        var headerSegment = Base64UrlEncoder.Encode(headerBytes);
        var payloadSegment = Base64UrlEncoder.Encode(payloadBytes);
        var signingInput = headerSegment + "." + payloadSegment;
        var signature = await key.SignAsync(Encoding.ASCII.GetBytes(signingInput), cancellationToken).ConfigureAwait(false);
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
