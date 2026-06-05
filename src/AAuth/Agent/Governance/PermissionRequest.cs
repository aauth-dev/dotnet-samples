using System;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>
/// A permission request the agent sends to the PS's <c>permission_endpoint</c>
/// (§Permission Request) for an action not governed by a remote resource — a
/// tool call, file write, or message send.
/// </summary>
/// <param name="Action">String identifying the action (e.g. a tool name). REQUIRED.</param>
public sealed record PermissionRequest(string Action)
{
    /// <summary>Markdown description of what the action will do and why. Optional.</summary>
    public string? Description { get; init; }

    /// <summary>The parameters the agent intends to pass to the action. Optional.</summary>
    public JsonObject? Parameters { get; init; }

    /// <summary>
    /// Mission binding (<c>approver</c> + <c>s256</c>). When present the PS
    /// evaluates the request against the mission context and log. Optional.
    /// </summary>
    public MissionClaim? Mission { get; init; }

    /// <summary>Render the request as the JSON request body.</summary>
    internal JsonObject ToJsonObject()
    {
        ArgumentException.ThrowIfNullOrEmpty(Action);
        var body = new JsonObject { ["action"] = Action };
        if (!string.IsNullOrEmpty(Description))
        {
            body["description"] = Description;
        }
        if (Parameters is not null)
        {
            body["parameters"] = Parameters.DeepClone();
        }
        if (Mission is not null)
        {
            body["mission"] = Mission.ToJsonObject();
        }
        return body;
    }
}
