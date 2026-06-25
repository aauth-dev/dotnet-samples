using System;
using System.Text.Json.Nodes;
using AAuth.Identifiers;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// The <c>mission</c> claim carried in resource and auth tokens (§Resource Token
/// Structure, §Auth Token Structure). Identifies the mission by its approver and
/// <c>s256</c> hash — the mission content itself never leaves the PS.
/// </summary>
/// <param name="Approver">HTTPS URL of the entity that approved the mission.</param>
/// <param name="S256">base64url(SHA-256) of the approved mission JSON.</param>
public sealed record MissionClaim(string Approver, string S256)
{
    /// <summary>Render the claim as the JSON object embedded in a token payload.</summary>
    public JsonObject ToJsonObject() => new()
    {
        ["approver"] = Approver,
        ["s256"] = S256,
    };

    /// <summary>
    /// Parse a <c>mission</c> claim from a token payload object. Returns
    /// <see langword="null"/> when the claim is absent or malformed.
    /// </summary>
    public static MissionClaim? FromPayload(JsonObject? payload)
    {
        if (payload?["mission"] is not JsonObject mission)
            return null;

        var approver = (string?)mission["approver"];
        var s256 = (string?)mission["s256"];
        if (string.IsNullOrEmpty(approver) || string.IsNullOrEmpty(s256))
            return null;

        // §Mission Reference: `approver` MUST be a Server Identifier (https,
        // scheme+host only) and `s256` MUST be the unpadded base64url of a 32-byte
        // SHA-256 digest. A non-conformant reference is dropped here so it cannot
        // govern a token request on the server's authorization path.
        if (!ServerId.TryParse(approver, out _, out _) || !IsValidMissionS256(s256))
            return null;

        return new MissionClaim(approver, s256);
    }

    // Unpadded base64url of exactly 32 bytes (SHA-256), per §Mission Reference.
    private static bool IsValidMissionS256(string value)
    {
        if (value.IndexOf('=') >= 0 || value.IndexOf('+') >= 0 || value.IndexOf('/') >= 0)
            return false;
        try
        {
            return Base64UrlEncoder.DecodeBytes(value).Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
