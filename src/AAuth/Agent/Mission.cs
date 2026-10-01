using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// An approved AAuth mission (§Mission Approval): the <em>mission blob</em>
/// returned by the PS's <c>mission_endpoint</c>, plus the approval response's
/// session members (<c>capabilities</c>, <c>person_tokens</c>).
/// </summary>
/// <remarks>
/// The mission's identity is its <see cref="S256"/>: the unpadded base64url
/// SHA-256 digest of the exact blob bytes. It travels as <c>mission_s256</c> in
/// person, resource and auth tokens and as the <c>mission_s256</c> parameter of
/// PS requests; the PS that approved it is named beside it.
/// </remarks>
public sealed class Mission
{
    /// <summary>The Person Server that approved the mission (the one the agent proposed to).</summary>
    public required string PersonServer { get; init; }

    /// <summary>The agent identifier (<c>aauth:local@domain</c>) the mission was approved for.</summary>
    public required string Agent { get; init; }

    /// <summary>When the mission was approved (ensures the <see cref="S256"/> is globally unique).</summary>
    public required DateTimeOffset ApprovedAt { get; init; }

    /// <summary>When set, the PS treats the mission as terminated after this instant.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

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

    /// <summary>The resources the person pre-approved for this mission (<c>approved_resources</c>).</summary>
    public IReadOnlyList<string> ApprovedResources { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Capability strings (e.g. <c>interaction</c>, <c>payment</c>) the PS can provide
    /// on behalf of the user for this session. The agent unions these with its own
    /// capabilities when constructing the <c>AAuth-Capabilities</c> request header.
    /// Not part of the blob or its digest.
    /// </summary>
    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Person tokens the PS issued with the approval, keyed by resource identifier,
    /// each carrying <c>mission_s256</c>. Not part of the blob or its digest.
    /// </summary>
    public IReadOnlyDictionary<string, string> PersonTokens { get; init; } = new Dictionary<string, string>();

    /// <summary>The mission identity: base64url(SHA-256(blob bytes)), carried as <c>mission_s256</c>.</summary>
    public required string S256 { get; init; }

    /// <summary>The verbatim mission blob bytes, so <see cref="S256"/> stays verifiable.</summary>
    public ReadOnlyMemory<byte> RawBytes { get; init; }

    /// <summary>The mission lifecycle state (§Mission Management).</summary>
    public MissionState State
    {
        get => (MissionState)System.Threading.Volatile.Read(ref _state);
        init => _state = (int)value;
    }

    private int _state = (int)MissionState.Active;

    internal void Terminate() => System.Threading.Interlocked.Exchange(ref _state, (int)MissionState.Terminated);

    internal void EnsureActive()
    {
        if (State == MissionState.Terminated
            || ExpiresAt is { } expiresAt && expiresAt <= DateTimeOffset.UtcNow)
            throw new AAuth.Errors.AAuthMissionTerminatedException("terminated");
    }

    internal async System.Threading.Tasks.Task<TResult> ExecuteAsync<TResult>(Func<System.Threading.Tasks.Task<TResult>> operation)
    {
        EnsureActive();
        try
        {
            var result = await operation().ConfigureAwait(false);
            EnsureActive();
            return result;
        }
        catch (AAuth.Errors.AAuthMissionTerminatedException)
        {
            Terminate();
            throw;
        }
    }

    /// <summary>
    /// Parse a §Mission Approval response body — <c>{ s256, mission, capabilities?,
    /// person_tokens? }</c> — decode the blob, and verify <c>s256</c> against it.
    /// </summary>
    /// <param name="body">The approval response body.</param>
    /// <param name="personServer">The PS the mission was proposed to.</param>
    /// <exception cref="InvalidOperationException">The response is malformed or <c>s256</c> does not match the blob.</exception>
    public static Mission FromApprovalResponse(ReadOnlySpan<byte> body, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        JsonObject envelope;
        try
        {
            envelope = JsonNode.Parse(body.ToArray()) as JsonObject
                ?? throw new InvalidOperationException("Mission approval response is not a JSON object.");
        }
        catch (JsonException ex) { throw new InvalidOperationException("Mission approval response is not valid JSON.", ex); }
        var s256 = (string?)envelope["s256"]
            ?? throw new InvalidOperationException("Mission approval response is missing 's256'.");
        var encoded = (string?)envelope["mission"]
            ?? throw new InvalidOperationException("Mission approval response is missing 'mission'.");
        byte[] blob;
        try { blob = Base64UrlEncoder.DecodeBytes(encoded); }
        catch (FormatException ex) { throw new InvalidOperationException("Mission approval 'mission' is not base64url.", ex); }
        var mission = FromBlob(blob, personServer,
            ParseStrings(envelope["capabilities"] as JsonArray), ParsePersonTokens(envelope["person_tokens"] as JsonObject));
        if (!mission.VerifyS256(s256))
            throw new InvalidOperationException("Mission approval 's256' does not match the mission blob.");
        return mission;
    }

    /// <summary>
    /// Parse a mission from its exact blob bytes and compute its <see cref="S256"/>.
    /// The bytes are stored verbatim in <see cref="RawBytes"/>.
    /// </summary>
    public static Mission FromBlob(ReadOnlySpan<byte> blob, string personServer,
        IReadOnlyList<string>? capabilities = null, IReadOnlyDictionary<string, string>? personTokens = null)
    {
        if (blob.IsEmpty)
            throw new ArgumentException("Mission blob is empty.", nameof(blob));
        ArgumentException.ThrowIfNullOrEmpty(personServer);

        var bytes = blob.ToArray();
        JsonObject json;
        try
        {
            json = JsonNode.Parse(bytes) as JsonObject
                ?? throw new InvalidOperationException("Mission blob is not a JSON object.");
        }
        catch (JsonException ex) { throw new InvalidOperationException("Mission blob is not valid JSON.", ex); }

        var agent = (string?)json["agent"]
            ?? throw new InvalidOperationException("Mission blob missing required 'agent'.");
        var description = (string?)json["description"]
            ?? throw new InvalidOperationException("Mission blob missing required 'description'.");
        if (json["approved_at"] is not JsonValue approvedAtValue
            || !TryParseIsoTimestamp((string?)approvedAtValue, out var approvedAt))
        {
            throw new InvalidOperationException("Mission blob missing or invalid 'approved_at'.");
        }
        DateTimeOffset? expiresAt = null;
        if (json["expires_at"] is { } expiresNode)
        {
            if (expiresNode is not JsonValue expiresValue || !TryParseIsoTimestamp((string?)expiresValue, out var parsedExpiry))
                throw new InvalidOperationException("Mission blob has an invalid 'expires_at'.");
            expiresAt = parsedExpiry;
        }

        return new Mission
        {
            PersonServer = personServer,
            Agent = agent,
            ApprovedAt = approvedAt,
            ExpiresAt = expiresAt,
            Description = description,
            ApprovedTools = ParseTools(json["approved_tools"] as JsonArray),
            ApprovedResources = ParseStrings(json["approved_resources"] as JsonArray),
            Capabilities = capabilities ?? Array.Empty<string>(),
            PersonTokens = personTokens ?? new Dictionary<string, string>(),
            S256 = ComputeS256(bytes),
            RawBytes = bytes,
        };
    }

    private static bool TryParseIsoTimestamp(string? value, out DateTimeOffset timestamp)
    {
        timestamp = default;
        string[] formats =
        [
            "O",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'",
            "yyyy-MM-dd'T'HH:mm:sszzz",
            "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz",
        ];
        return value is not null && DateTimeOffset.TryParseExact(
            value, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out timestamp);
    }

    /// <summary>Verify that <paramref name="expected"/> matches the <see cref="S256"/> of the stored blob bytes.</summary>
    public bool VerifyS256(string expected)
    {
        if (string.IsNullOrEmpty(expected))
            return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(S256),
            Encoding.ASCII.GetBytes(expected));
    }

    /// <summary>Compute base64url(SHA-256(<paramref name="body"/>)) per §Mission Identifier.</summary>
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

    private static IReadOnlyList<string> ParseStrings(JsonArray? values)
    {
        if (values is null || values.Count == 0)
            return Array.Empty<string>();

        var result = new List<string>(values.Count);
        foreach (var node in values)
        {
            if (node is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrEmpty(text))
                result.Add(text);
        }

        return result;
    }

    private static IReadOnlyDictionary<string, string> ParsePersonTokens(JsonObject? tokens)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (resource, node) in tokens ?? [])
        {
            if (node is JsonValue value && value.TryGetValue<string>(out var token) && !string.IsNullOrEmpty(token))
                result[resource] = token;
        }
        return result;
    }
}
