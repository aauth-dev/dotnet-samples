using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Server.Governance;

/// <summary>
/// Builds the verbatim mission blob and approval response (§Mission Approval).
/// The blob bytes are returned exactly as they will be persisted and sent, so the
/// <c>s256</c> the PS returns matches what the agent computes over the same bytes.
/// This is the canonical default used by <c>MapAAuthGovernance</c>.
/// </summary>
public static class MissionApprovalBuilder
{
    /// <summary>
    /// Build the mission blob bytes and their <c>s256</c> identity for an approved mission.
    /// </summary>
    /// <param name="agent">The agent the mission is approved for.</param>
    /// <param name="proposal">The proposed mission (its description is copied verbatim).</param>
    /// <param name="approvedTools">The tools the PS approved (a subset of the proposed tools).</param>
    /// <param name="approvedAt">The approval timestamp.</param>
    /// <param name="expiresAt">Optional <c>expires_at</c>.</param>
    /// <param name="approvedResources">Optional <c>approved_resources</c>, drawn from the proposal's resources.</param>
    /// <returns>The exact blob bytes and their base64url(SHA-256) identity.</returns>
    public static (byte[] Blob, string S256) Build(
        string agent,
        MissionProposal proposal,
        IReadOnlyList<MissionTool> approvedTools,
        DateTimeOffset approvedAt,
        DateTimeOffset? expiresAt = null,
        IReadOnlyList<string>? approvedResources = null)
    {
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
            ["agent"] = agent,
            ["approved_at"] = approvedAt.ToString("o"),
        };
        if (expiresAt is { } expiry) blob["expires_at"] = expiry.ToString("o");
        blob["description"] = proposal.Description;
        blob["approved_tools"] = tools;
        if (approvedResources is { Count: > 0 })
        {
            var resources = new JsonArray();
            foreach (var resource in approvedResources) resources.Add(resource);
            blob["approved_resources"] = resources;
        }

        var bytes = Encoding.UTF8.GetBytes(blob.ToJsonString());
        return (bytes, Mission.ComputeS256(bytes));
    }

    /// <summary>
    /// The §Mission Approval response body: <c>{ s256, mission, capabilities?, person_tokens? }</c>,
    /// where <c>mission</c> is the unpadded base64url encoding of <paramref name="blob"/>.
    /// </summary>
    public static JsonObject Response(
        ReadOnlySpan<byte> blob, string s256,
        IReadOnlyList<string>? capabilities = null,
        IReadOnlyDictionary<string, string>? personTokens = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        var body = new JsonObject
        {
            ["s256"] = s256,
            ["mission"] = Base64UrlEncoder.Encode(blob.ToArray()),
        };
        if (capabilities is { Count: > 0 })
        {
            var values = new JsonArray();
            foreach (var capability in capabilities) values.Add(capability);
            body["capabilities"] = values;
        }
        // Present whenever the PS issued for named resources, even if it declined them all.
        if (personTokens is not null)
        {
            var tokens = new JsonObject();
            foreach (var (resource, token) in personTokens) tokens[resource] = token;
            body["person_tokens"] = tokens;
        }
        return body;
    }
}
