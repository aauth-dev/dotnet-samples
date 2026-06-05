using System.Text.Json.Nodes;

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

        return new MissionClaim(approver, s256);
    }
}
