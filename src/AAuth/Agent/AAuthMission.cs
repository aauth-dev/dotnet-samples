using System;
using System.Text.Json.Nodes;

namespace AAuth.Agent;

/// <summary>
/// Represents an AAuth mission (§5) — a structured request for
/// multi-step approval, clarification, or audited access.
/// Agent-side model parsed from PS responses.
/// </summary>
public sealed class AAuthMission
{
    /// <summary>Mission identifier.</summary>
    public required string Id { get; init; }

    /// <summary>Mission status (pending, approved, denied, completed).</summary>
    public required string Status { get; init; }

    /// <summary>Required permissions or clarifications.</summary>
    public JsonArray? Requirements { get; init; }

    /// <summary>Human-readable description of what the mission is for.</summary>
    public string? Description { get; init; }

    /// <summary>URL to check mission status.</summary>
    public string? StatusUrl { get; init; }

    /// <summary>URL for human interaction (approval UI).</summary>
    public string? InteractionUrl { get; init; }

    /// <summary>Parse from a JSON response body.</summary>
    public static AAuthMission FromJson(JsonObject json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return new AAuthMission
        {
            Id = (string?)json["mission_id"] ?? throw new InvalidOperationException("Missing 'mission_id'."),
            Status = (string?)json["status"] ?? "pending",
            Requirements = json["requirements"] as JsonArray,
            Description = (string?)json["description"],
            StatusUrl = (string?)json["status_url"],
            InteractionUrl = (string?)json["interaction_url"],
        };
    }
}

/// <summary>
/// The AAuth-Mission header value, used by the agent to declare its mission
/// context on outbound requests.
/// </summary>
public static class AAuthMissionHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "AAuth-Mission";

    /// <summary>Format the header value with a mission ID.</summary>
    public static string Format(string missionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(missionId);
        return missionId;
    }
}
