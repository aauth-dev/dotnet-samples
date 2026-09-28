using System;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// The <c>mission_s256</c> claim and parameter: the unpadded base64url SHA-256 of
/// the approved mission blob. It names a mission; the approving PS is the issuer
/// of the token that carries it (§Missions).
/// </summary>
public static class MissionReference
{
    /// <summary>The claim and request-parameter name.</summary>
    public const string ClaimName = "mission_s256";

    /// <summary>Whether <paramref name="value"/> is an unpadded base64url SHA-256 digest.</summary>
    public static bool IsValid(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.IndexOfAny(['=', '+', '/']) >= 0)
            return false;
        try { return Base64UrlEncoder.DecodeBytes(value).Length == 32 && Base64UrlEncoder.Encode(Base64UrlEncoder.DecodeBytes(value)) == value; }
        catch (FormatException) { return false; }
    }

    /// <summary>
    /// Read <c>mission_s256</c> from a token payload or request body. Returns
    /// <see langword="null"/> when absent; throws when present but malformed.
    /// </summary>
    public static string? Read(JsonObject? document)
    {
        if (document is null || !document.ContainsKey(ClaimName))
            return null;
        var value = document[ClaimName] is JsonValue node && node.TryGetValue<string>(out var text) ? text : null;
        return IsValid(value) ? value : throw new TokenVerificationException("mission_s256 must be an unpadded base64url SHA-256 digest.");
    }
}
