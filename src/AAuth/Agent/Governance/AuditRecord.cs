using System;
using System.Text.Json.Nodes;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>
/// An audit record the agent sends to the PS's <c>audit_endpoint</c>
/// (§Audit Request) after performing an action. The audit endpoint requires a
/// mission — there is no audit outside a mission context.
/// </summary>
/// <param name="Mission">Mission binding (<c>approver</c> + <c>s256</c>). REQUIRED.</param>
/// <param name="Action">String identifying the action that was performed. REQUIRED.</param>
public sealed record AuditRecord(MissionClaim Mission, string Action)
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
        ArgumentNullException.ThrowIfNull(Mission);
        ArgumentException.ThrowIfNullOrEmpty(Action);
        var body = new JsonObject
        {
            ["mission"] = Mission.ToJsonObject(),
            ["action"] = Action,
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
