using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace AAuth.Agent.Governance;

/// <summary>
/// A mission proposal the agent sends to the PS's <c>mission_endpoint</c>
/// (§Mission Creation). Carries a Markdown description of what the agent intends
/// to accomplish and, optionally, the tools it wants to use.
/// </summary>
/// <param name="Description">Markdown description of the intended mission.</param>
public sealed record MissionProposal(string Description)
{
    /// <summary>
    /// Tools the agent wants to use. The approved mission MAY grant a subset
    /// (§Mission Approval). Optional.
    /// </summary>
    public IReadOnlyList<MissionTool> Tools { get; init; } = Array.Empty<MissionTool>();

    /// <summary>Render the proposal as the JSON request body.</summary>
    internal JsonObject ToJsonObject()
    {
        ArgumentException.ThrowIfNullOrEmpty(Description);
        var body = new JsonObject { ["description"] = Description };
        if (Tools.Count > 0)
        {
            var tools = new JsonArray();
            foreach (var tool in Tools)
            {
                var obj = new JsonObject { ["name"] = tool.Name };
                if (!string.IsNullOrEmpty(tool.Description))
                {
                    obj["description"] = tool.Description;
                }
                tools.Add(obj);
            }
            body["tools"] = tools;
        }
        return body;
    }
}
