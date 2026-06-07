namespace AAuth.Agent;

/// <summary>
/// The lifecycle state of a mission (§Mission Management). A mission has exactly
/// one of two states.
/// </summary>
public enum MissionState
{
    /// <summary>The mission is in progress. The agent can make requests against it.</summary>
    Active,

    /// <summary>
    /// The mission is permanently ended. The PS MUST reject requests with
    /// <c>mission_terminated</c> (§Mission Status Errors).
    /// </summary>
    Terminated,
}
