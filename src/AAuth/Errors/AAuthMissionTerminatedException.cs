using System;

namespace AAuth.Errors;

/// <summary>
/// Thrown when an agent makes a request to a PS endpoint carrying a
/// <c>mission</c> parameter that references a mission that is no longer
/// active. The PS responds with <c>403 Forbidden</c> and a JSON body
/// <c>{ "error": "mission_terminated", "mission_status": "terminated" }</c>
/// (AAuth protocol §Mission Status Errors). The agent MUST stop acting on
/// the mission.
/// </summary>
/// <remarks>
/// Distinct from <see cref="AAuthTokenExchangeException"/> (token-endpoint
/// error bodies) and the agent-side interaction exceptions so callers can
/// branch specifically on a terminated mission and unwind the mission's work.
/// </remarks>
public sealed class AAuthMissionTerminatedException : Exception
{
    /// <summary>The wire <c>error</c> code: <c>mission_terminated</c>.</summary>
    public const string ErrorCode = "mission_terminated";

    /// <summary>The <c>mission_status</c> value from the response body, when present.</summary>
    public string? MissionStatus { get; }

    /// <summary>
    /// The OPTIONAL <c>termination_reason</c> from the response body, such as
    /// <c>expired</c> (a new mission may be proposed) or <c>revoked</c> (it may not).
    /// </summary>
    public string? TerminationReason { get; }

    /// <summary>Create a mission-terminated exception.</summary>
    public AAuthMissionTerminatedException(string? missionStatus = null, string? terminationReason = null)
        : base("The mission is permanently terminated; the agent must stop acting on it.")
    {
        MissionStatus = missionStatus;
        TerminationReason = terminationReason;
    }

    /// <summary>Create a mission-terminated exception with a custom message.</summary>
    public AAuthMissionTerminatedException(string message, string? missionStatus, string? terminationReason = null)
        : base(message)
    {
        MissionStatus = missionStatus;
        TerminationReason = terminationReason;
    }
}
