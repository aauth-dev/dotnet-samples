using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// Builds the verbatim mission approval blob (§Mission Approval). The bytes are
/// returned exactly as they will be sent, so the <c>s256</c> the PS advertises in
/// the <c>AAuth-Mission</c> header matches what the agent computes over the same
/// bytes. A PS that needs a different on-the-wire shape can build its own blob;
/// this is the canonical default used by <c>MapAAuthGovernance</c>.
/// </summary>
public static class MissionApprovalBuilder
{
    /// <summary>
    /// Build the approval blob bytes and their <c>s256</c> identity for an
    /// approved mission.
    /// </summary>
    /// <param name="approver">HTTPS URL of the approver (the PS).</param>
    /// <param name="agent">The agent the mission is approved for.</param>
    /// <param name="proposal">The proposed mission (its description is copied verbatim).</param>
    /// <param name="approvedTools">The tools the PS approved (a subset of the proposed tools).</param>
    /// <param name="approvedAt">The approval timestamp.</param>
    /// <returns>The exact blob bytes and their base64url(SHA-256) identity.</returns>
    public static (byte[] Blob, string S256) Build(
        string approver,
        string agent,
        MissionProposal proposal,
        IReadOnlyList<MissionTool> approvedTools,
        DateTimeOffset approvedAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(approver);
        ArgumentException.ThrowIfNullOrEmpty(agent);
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(approvedTools);

        var tools = new JsonArray();
        foreach (var tool in approvedTools)
        {
            var obj = new JsonObject { ["name"] = tool.Name };
            if (!string.IsNullOrEmpty(tool.Description))
            {
                obj["description"] = tool.Description;
            }
            tools.Add(obj);
        }

        var blob = new JsonObject
        {
            ["approver"] = approver,
            ["agent"] = agent,
            ["approved_at"] = approvedAt.ToString("o"),
            ["description"] = proposal.Description,
            ["approved_tools"] = tools,
        };

        var bytes = Encoding.UTF8.GetBytes(blob.ToJsonString());
        return (bytes, Mission.ComputeS256(bytes));
    }
}
