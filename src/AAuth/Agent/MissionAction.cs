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
/// <c>approved_tools</c>). A pre-approved tool can be invoked directly via the
/// implicit conversion from <see cref="MissionTool"/>, and a bare action name via
/// the implicit conversion from <see cref="string"/>.
/// </remarks>
/// <param name="Name">The action identifier serialized as the wire <c>action</c>. REQUIRED.</param>
public sealed record MissionAction(string Name)
{
    /// <summary>A bare action name (e.g. <c>"WebSearch"</c>) is a <see cref="MissionAction"/>.</summary>
    public static implicit operator MissionAction(string name) => new(name);

    /// <summary>Invoke a catalog <see cref="MissionTool"/> as an action by its name.</summary>
    public static implicit operator MissionAction(MissionTool tool) => new(tool.Name);

    /// <inheritdoc />
    public override string ToString() => Name;
}
