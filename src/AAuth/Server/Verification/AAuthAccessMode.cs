namespace AAuth.Server.Verification;

/// <summary>
/// Specifies how a resource handles access decisions after identity verification.
/// </summary>
public enum AAuthAccessMode
{
    /// <summary>
    /// Accept any verified identity (agent token or auth token) without
    /// requiring an auth token upgrade. The resource trusts identity alone.
    /// </summary>
    IdentityOnly,

    /// <summary>
    /// Require an auth token. If the caller presents only an agent token,
    /// the middleware issues a 401 challenge with a resource token so the
    /// agent can obtain an auth token from the PS/AS.
    /// </summary>
    RequireAuthToken,

    /// <summary>
    /// Require the agent's own AAuth agent token (<c>typ: aa-agent+jwt</c>).
    /// If the caller presents no agent token, the middleware issues a 401
    /// challenge with a bare <c>AAuth-Requirement: requirement=agent-token</c>
    /// (no resource token, no PS/AS involved) — the agent need only present the
    /// agent token it already holds (§Agent Token Required).
    /// </summary>
    AgentTokenRequired,
}
