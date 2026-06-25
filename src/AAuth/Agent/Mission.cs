using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Identifiers;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// An approved AAuth mission (§Mission Approval) — the <em>mission blob</em>
/// returned by the PS's <c>mission_endpoint</c>. A mission is a scoped
/// authorization context that the PS uses to evaluate every subsequent request
/// in context.
/// </summary>
/// <remarks>
/// The mission's identity is its <see cref="S256"/>: the base64url-encoded
/// SHA-256 hash of the exact approval response body bytes. Per spec, the agent
/// MUST store the mission body bytes exactly as received — no re-serialization —
/// so the hash can be verified and the same value carried in the
/// <c>AAuth-Mission</c> header on subsequent requests.
/// </remarks>
public sealed class Mission
{
    /// <summary>HTTPS URL of the entity that approved the mission (currently always the PS).</summary>
    public required string Approver { get; init; }

    /// <summary>The agent identifier (<c>aauth:local@domain</c>) the mission was approved for.</summary>
    public required string Agent { get; init; }

    /// <summary>When the mission was approved (ensures the <see cref="S256"/> is globally unique).</summary>
    public required DateTimeOffset ApprovedAt { get; init; }

    /// <summary>
    /// Markdown string describing the approved mission scope. This is
    /// server-supplied, untrusted content: consumers MUST sanitize it before
    /// rendering it to a user (§Markdown).
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Tools the agent may use without a per-call permission request at the PS's
    /// permission endpoint (§Permission Endpoint). MAY be a subset of the proposed tools.
    /// </summary>
    public IReadOnlyList<MissionTool> ApprovedTools { get; init; } = Array.Empty<MissionTool>();

    /// <summary>
    /// Capability strings (e.g. <c>interaction</c>, <c>payment</c>) the PS can provide
    /// on behalf of the user for this session. The agent unions these with its own
    /// capabilities when constructing the <c>AAuth-Capabilities</c> request header.
    /// </summary>
    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    /// <summary>
    /// The mission identity: base64url(SHA-256(approval body bytes)). Carried in the
    /// <c>AAuth-Mission</c> header and embedded as the <c>mission</c> claim in tokens.
    /// </summary>
    public required string S256 { get; init; }

    /// <summary>
    /// The verbatim approval response body bytes, stored exactly as received so the
    /// <see cref="S256"/> can be verified without re-serialization.
    /// </summary>
    public ReadOnlyMemory<byte> RawBytes { get; init; }

    /// <summary>The mission lifecycle state (§Mission Management).</summary>
    public MissionState State { get; init; } = MissionState.Active;

    /// <summary>
    /// Parse a mission from the exact approval response body bytes and compute its
    /// <see cref="S256"/> identity. The bytes are stored verbatim in
    /// <see cref="RawBytes"/> — they are never re-serialized.
    /// </summary>
    public static Mission FromApprovalBytes(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            throw new ArgumentException("Mission approval body is empty.", nameof(body));

        var bytes = body.ToArray();

        if (JsonNode.Parse(bytes) is not JsonObject json)
            throw new InvalidOperationException("Mission approval body is not a JSON object.");

        var approver = (string?)json["approver"]
            ?? throw new InvalidOperationException("Mission blob missing required 'approver'.");
        var agent = (string?)json["agent"]
            ?? throw new InvalidOperationException("Mission blob missing required 'agent'.");
        var description = (string?)json["description"]
            ?? throw new InvalidOperationException("Mission blob missing required 'description'.");

        if (json["approved_at"] is not JsonValue approvedAtValue
            || !DateTimeOffset.TryParse((string?)approvedAtValue, out var approvedAt))
        {
            throw new InvalidOperationException("Mission blob missing or invalid 'approved_at'.");
        }

        return new Mission
        {
            Approver = approver,
            Agent = agent,
            ApprovedAt = approvedAt,
            Description = description,
            ApprovedTools = ParseTools(json["approved_tools"] as JsonArray),
            Capabilities = ParseCapabilities(json["capabilities"] as JsonArray),
            S256 = ComputeS256(bytes),
            RawBytes = bytes,
        };
    }

    /// <summary>
    /// Verify that the supplied value (e.g. from the <c>AAuth-Mission</c> header) matches
    /// the <see cref="S256"/> computed over the stored approval body bytes.
    /// </summary>
    public bool VerifyS256(string expected)
    {
        if (string.IsNullOrEmpty(expected))
            return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(S256),
            Encoding.ASCII.GetBytes(expected));
    }

    /// <summary>Compute base64url(SHA-256(<paramref name="body"/>)) per §Mission Approval.</summary>
    public static string ComputeS256(ReadOnlySpan<byte> body)
    {
        var hash = SHA256.HashData(body);
        return Base64UrlEncoder.Encode(hash);
    }

    private static IReadOnlyList<MissionTool> ParseTools(JsonArray? tools)
    {
        if (tools is null || tools.Count == 0)
            return Array.Empty<MissionTool>();

        var result = new List<MissionTool>(tools.Count);
        foreach (var node in tools)
        {
            if (node is not JsonObject tool)
                continue;
            var name = (string?)tool["name"];
            if (string.IsNullOrEmpty(name))
                continue;
            result.Add(new MissionTool(name, (string?)tool["description"]));
        }

        return result;
    }

    private static IReadOnlyList<string> ParseCapabilities(JsonArray? capabilities)
    {
        if (capabilities is null || capabilities.Count == 0)
            return Array.Empty<string>();

        var result = new List<string>(capabilities.Count);
        foreach (var node in capabilities)
        {
            var value = (string?)node;
            if (!string.IsNullOrEmpty(value))
                result.Add(value);
        }

        return result;
    }
}

/// <summary>
/// The AAuth-Mission header value, used by the agent to declare its mission
/// context on outbound requests (§AAuth-Mission Request Header).
/// </summary>
public static class AAuthMissionHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "AAuth-Mission";

    /// <summary>
    /// Format the structured header value with approver and s256 per §Call Chaining.
    /// </summary>
    /// <remarks>
    /// Produces: <c>approver="https://ps.example"; s256="dBjf..."</c>
    /// </remarks>
    public static string FormatStructured(string approver, string s256)
    {
        ArgumentException.ThrowIfNullOrEmpty(approver);
        ArgumentException.ThrowIfNullOrEmpty(s256);
        return $"approver=\"{approver}\"; s256=\"{s256}\"";
    }

    /// <summary>
    /// Parse a structured <c>AAuth-Mission</c> header value into its
    /// <c>approver</c> and <c>s256</c> components (§Call Chaining). Returns
    /// <see langword="false"/> when the value is absent or either field is missing.
    /// </summary>
    public static bool TryParseStructured(string? value, out string? approver, out string? s256)
    {
        approver = null;
        s256 = null;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        foreach (var part in value.Split(';'))
        {
            var trimmed = part.Trim();
            var eq = trimmed.IndexOf('=');
            if (eq <= 0)
                continue;
            var name = trimmed[..eq].Trim();
            var raw = trimmed[(eq + 1)..].Trim().Trim('"');
            if (raw.Length == 0)
                continue;
            if (name.Equals("approver", StringComparison.OrdinalIgnoreCase))
                approver = raw;
            else if (name.Equals("s256", StringComparison.OrdinalIgnoreCase))
                s256 = raw;
        }

        if (string.IsNullOrEmpty(approver) || string.IsNullOrEmpty(s256))
        {
            approver = null;
            s256 = null;
            return false;
        }

        // §Mission Reference: `approver` MUST be a Server Identifier (https,
        // scheme+host only, no port/path/query/fragment) and `s256` MUST be the
        // unpadded base64url encoding of a 32-byte SHA-256 digest. A reference that
        // does not conform is rejected — the malformed mission is dropped.
        if (!ServerId.TryParse(approver, out _, out _) || !IsValidMissionS256(s256))
        {
            approver = null;
            s256 = null;
            return false;
        }

        return true;
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
