using System;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>
/// An audit record the agent sends to the PS's <c>audit_endpoint</c>
/// (§Audit Request) after performing an action. The audit endpoint requires a
/// mission — there is no audit outside a mission context.
/// </summary>
/// <param name="MissionS256">The mission (<c>mission_s256</c>). REQUIRED.</param>
/// <param name="Action">The action that was performed. REQUIRED.</param>
public sealed record AuditRecord(string MissionS256, MissionAction Action)
{
    /// <summary>Markdown description of what was done and the outcome. Optional.</summary>
    public string? Description { get; init; }

    /// <summary>The parameters that were used. Optional.</summary>
    public JsonObject? Parameters { get; init; }

    /// <summary>The result or outcome of the action. Optional.</summary>
    public JsonObject? Result { get; init; }

    /// <summary>Render the record as the JSON request body.</summary>
    internal JsonObject ToJsonObject()
    {
        ArgumentException.ThrowIfNullOrEmpty(MissionS256);
        ArgumentNullException.ThrowIfNull(Action);
        ArgumentException.ThrowIfNullOrEmpty(Action.Name);
        var body = new JsonObject
        {
            ["mission_s256"] = MissionS256,
            ["action"] = Action.Name,
        };
        if (!string.IsNullOrEmpty(Description))
        {
            body["description"] = Description;
        }
        if (Parameters is not null)
        {
            body["parameters"] = Parameters.DeepClone();
        }
        if (Result is not null)
        {
            body["result"] = Result.DeepClone();
        }
        return body;
    }
}
