namespace AAuth.Agent;

/// <summary>
/// A tool the agent may use within a mission. Mission proposals carry requested
/// tools; the approved mission blob carries <c>approved_tools</c> that the agent
/// may use without a per-call permission request (§Mission Approval).
/// </summary>
/// <param name="Name">The tool name.</param>
/// <param name="Description">A human-readable description of the tool.</param>
public sealed record MissionTool(string Name, string? Description = null);
