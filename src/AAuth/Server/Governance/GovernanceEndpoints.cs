using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Errors;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.Governance;

/// <summary>
/// Minimal server-side helpers for the PS governance endpoints
/// (§PS Governance Endpoints): request-body parsers that map JSON to the shared
/// DTOs, and the canonical <c>mission_terminated</c> response
/// (§Mission Status Errors). Policy and the user channel stay in the PS; this
/// type only removes hand-rolled parsing.
/// </summary>
public static class GovernanceEndpoints
{
    /// <summary>HTTP status for a terminated mission (§Mission Status Errors).</summary>
    public const int MissionTerminatedStatus = StatusCodes.Status403Forbidden;

    /// <summary>
    /// Parse a permission request body (§Permission Request) into a
    /// <see cref="PermissionRequest"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>action</c> is missing.</exception>
    public static PermissionRequest ParsePermission(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var action = (string?)body["action"]
            ?? throw new FormatException("Permission request is missing the required 'action'.");
        return new PermissionRequest(new MissionAction(action))
        {
            Description = (string?)body["description"],
            Parameters = body["parameters"] as JsonObject,
            Mission = MissionClaim.FromPayload(body),
        };
    }

    /// <summary>
    /// Parse an audit request body (§Audit Request) into an <see cref="AuditRecord"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>mission</c> or <c>action</c> is missing.</exception>
    public static AuditRecord ParseAudit(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var mission = MissionClaim.FromPayload(body)
            ?? throw new FormatException("Audit request is missing the required 'mission'.");
        var action = (string?)body["action"]
            ?? throw new FormatException("Audit request is missing the required 'action'.");
        return new AuditRecord(mission, new MissionAction(action))
        {
            Description = (string?)body["description"],
            Parameters = body["parameters"] as JsonObject,
            Result = body["result"] as JsonObject,
        };
    }

    /// <summary>
    /// Parse an interaction request body (§Interaction Request) into an
    /// <see cref="InteractionRequest"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>type</c> is missing or unknown.</exception>
    public static InteractionRequest ParseInteraction(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var typeValue = (string?)body["type"]
            ?? throw new FormatException("Interaction request is missing the required 'type'.");
        var type = typeValue switch
        {
            "interaction" => InteractionType.Interaction,
            "payment" => InteractionType.Payment,
            "question" => InteractionType.Question,
            "completion" => InteractionType.Completion,
            _ => throw new FormatException($"Interaction request has an unknown 'type': {typeValue}"),
        };
        return new InteractionRequest(type)
        {
            Description = (string?)body["description"],
            Url = (string?)body["url"],
            Code = (string?)body["code"],
            Question = (string?)body["question"],
            Summary = (string?)body["summary"],
            Mission = MissionClaim.FromPayload(body),
        };
    }

    /// <summary>
    /// Parse a mission proposal body (§Mission Creation) into a
    /// <see cref="MissionProposal"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>description</c> is missing.</exception>
    public static MissionProposal ParseMissionProposal(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var description = (string?)body["description"]
            ?? throw new FormatException("Mission proposal is missing the required 'description'.");
        return new MissionProposal(description)
        {
            Tools = ParseTools(body["tools"] as JsonArray),
        };
    }

    /// <summary>
    /// The canonical <c>mission_terminated</c> response body (§Mission Status
    /// Errors): <c>{ "error": "mission_terminated", "mission_status": "..." }</c>.
    /// </summary>
    public static JsonObject MissionTerminatedBody(string missionStatus = "terminated")
        => new()
        {
            ["error"] = AAuthMissionTerminatedException.ErrorCode,
            ["mission_status"] = missionStatus,
        };

    /// <summary>
    /// An ASP.NET Core <see cref="IResult"/> emitting the spec
    /// <c>403 mission_terminated</c> response (§Mission Status Errors).
    /// </summary>
    public static IResult MissionTerminated(string missionStatus = "terminated")
        => Results.Json(MissionTerminatedBody(missionStatus), statusCode: MissionTerminatedStatus);

    private static IReadOnlyList<MissionTool> ParseTools(JsonArray? tools)
    {
        if (tools is null || tools.Count == 0)
        {
            return Array.Empty<MissionTool>();
        }
        var result = new List<MissionTool>(tools.Count);
        foreach (var node in tools)
        {
            if (node is not JsonObject tool)
            {
                continue;
            }
            var name = (string?)tool["name"];
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }
            result.Add(new MissionTool(name, (string?)tool["description"]));
        }
        return result;
    }
}
