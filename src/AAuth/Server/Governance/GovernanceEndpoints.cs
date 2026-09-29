using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Errors;
using AAuth.Server.Verification;
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
    /// Authorize a governance request: the carrier is a verified agent token and,
    /// when <paramref name="missionS256"/> is present, the mission exists, is this
    /// agent's, and is active. A missing and a foreign mission are indistinguishable
    /// (<c>mission_not_found</c>, §Mission Endpoint Errors).
    /// </summary>
    public static IResult? Authorize(HttpContext context, string? missionS256, StoredMission? mission)
    {
        var verified = context.GetAAuthVerification();
        if (verified is not { TokenType: AAuthTokenType.AgentToken, IssuerVerified: true, Agent: not null })
        {
            return AAuthProblemDetails.Create("invalid_request", "Governance endpoints require an agent token.", statusCode: StatusCodes.Status403Forbidden);
        }
        if (missionS256 is null) return null;
        if (mission is null || mission.S256 != missionS256 || mission.Agent != verified.Agent)
        {
            return AAuthProblemDetails.Create("mission_not_found", statusCode: StatusCodes.Status404NotFound);
        }
        return mission.State == MissionState.Terminated
            || mission.ExpiresAt is { } expiresAt && expiresAt <= DateTimeOffset.UtcNow
            ? MissionTerminated() : null;
    }

    private static string? ReadMission(JsonObject body)
    {
        try { return MissionReference.Read(body); }
        catch (TokenVerificationException ex) { throw new FormatException(ex.Message, ex); }
    }

    /// <summary>
    /// Parse a permission request body (§Permission Request) into a
    /// <see cref="PermissionRequest"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>action</c> is missing, or <c>mission_s256</c> is malformed.</exception>
    public static PermissionRequest ParsePermission(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var action = (string?)body["action"]
            ?? throw new FormatException("Permission request is missing the required 'action'.");
        return new PermissionRequest(new MissionAction(action))
        {
            Description = (string?)body["description"],
            Parameters = body["parameters"] as JsonObject,
            MissionS256 = ReadMission(body),
        };
    }

    /// <summary>
    /// Parse an audit request body (§Audit Request) into an <see cref="AuditRecord"/>.
    /// </summary>
    /// <exception cref="FormatException">The required <c>mission_s256</c> or <c>action</c> is missing.</exception>
    public static AuditRecord ParseAudit(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var mission = ReadMission(body)
            ?? throw new FormatException("Audit request is missing the required 'mission_s256'.");
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
            // §Interaction Endpoint: completion belongs at the mission endpoint.
            _ => throw new FormatException($"Interaction request has an unknown 'type': {typeValue}"),
        };
        return new InteractionRequest(type)
        {
            Description = (string?)body["description"],
            Url = (string?)body["url"],
            Code = (string?)body["code"],
            Question = (string?)body["question"],
            Summary = (string?)body["summary"],
            MaxWait = (int?)body["max_wait"],
            MissionS256 = ReadMission(body),
        };
    }

    /// <summary>
    /// Parse a mission proposal body (§Mission Creation) into a
    /// <see cref="MissionProposal"/>.
    /// </summary>
    /// <param name="body">The proposal JSON body.</param>
    /// <param name="egressPolicy">Validates each <c>resources</c> identifier; defaults to the production (HTTPS-only) policy.</param>
    /// <exception cref="FormatException">The required <c>description</c> is missing, or a <c>resources</c> entry is not a valid server identifier.</exception>
    public static MissionProposal ParseMissionProposal(JsonObject body, AAuth.Discovery.AAuthEgressPolicy? egressPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(body);
        var description = (string?)body["description"]
            ?? throw new FormatException("Mission proposal is missing the required 'description'.");
        return new MissionProposal(description)
        {
            Tools = ParseTools(body["tools"] as JsonArray),
            Resources = ParseResources(body["resources"] as JsonArray, egressPolicy),
        };
    }

    private static IReadOnlyList<string> ParseResources(JsonArray? resources, AAuth.Discovery.AAuthEgressPolicy? egressPolicy)
    {
        var result = new List<string>();
        foreach (var node in resources ?? [])
        {
            if (node is not JsonValue value || !value.TryGetValue<string>(out var resource)
                || !AAuthUrl.IsHttpsOrLoopback(resource, egressPolicy))
                throw new FormatException("Mission proposal 'resources' must be HTTPS server identifiers.");
            result.Add(resource);
        }
        return result;
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
        => AAuthProblemDetails.Create(AAuthMissionTerminatedException.ErrorCode,
            statusCode: MissionTerminatedStatus,
            extensions: new Dictionary<string, object?> { ["mission_status"] = missionStatus });

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
