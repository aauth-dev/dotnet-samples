namespace AAuth.Agent;

/// <summary>
/// A specific action the agent invokes within a mission — the <c>action</c> sent
/// to the PS's permission and audit endpoints (§Permission Endpoint, §Audit
/// Endpoint). The spec defines <c>action</c> as "a string identifying the action
/// the agent wants to perform (e.g., a tool name)", so it is broader than a tool:
/// it also covers file writes, message sends, and other governed operations.
/// </summary>
/// <remarks>
/// <see cref="MissionAction"/> is the <em>invocation</em>; <see cref="MissionTool"/>
/// is the <em>catalog</em> entry (a proposal's requested tools / the approval's
/// <c>approved_tools</c>). A pre-approved tool can be invoked as an action via
/// <see cref="MissionTool.ToAction"/>. Callers always name the action explicitly
/// (<c>new MissionAction("WebSearch")</c>); the SDK serializes <see cref="Name"/>
/// as the wire <c>action</c> string.
/// </remarks>
/// <param name="Name">The action identifier serialized as the wire <c>action</c>. REQUIRED.</param>
public sealed record MissionAction(string Name)
{
    /// <inheritdoc />
    public override string ToString() => Name;
}
