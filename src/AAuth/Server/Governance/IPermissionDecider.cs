using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>The PS's outcome for a permission request (§Permission Response).</summary>
public enum PermissionOutcome
{
    /// <summary>Grant without prompting the user.</summary>
    Granted,

    /// <summary>Deny without prompting the user.</summary>
    Denied,

    /// <summary>Defer — the PS must prompt the user before deciding.</summary>
    Prompt,
}

/// <summary>
/// Why the PS reached a permission decision. The SDK supplies the reason enum so
/// a PS can surface it to UIs and the mission log; the PS owns the policy
/// (§Agent Token Request, §Permission Endpoint).
/// </summary>
public enum PermissionDecisionReason
{
    /// <summary>The action is within the mission's approved scope.</summary>
    InScope,

    /// <summary>The user previously consented to an equivalent action.</summary>
    PriorConsent,

    /// <summary>The action is a pre-approved tool on the mission (<c>approved_tools</c>).</summary>
    ApprovedTool,

    /// <summary>The action is outside known scope — the user must be prompted.</summary>
    OutOfScope,
}

/// <summary>
/// The inputs a PS evaluates when deciding a permission request: the request
/// itself, the mission it is bound to (if any), and the mission log history.
/// </summary>
/// <param name="Request">The parsed permission request.</param>
/// <param name="Mission">The bound mission, or <see langword="null"/> when missionless.</param>
/// <param name="Log">The mission log entries (empty when missionless).</param>
public sealed record PermissionDecisionContext(
    PermissionRequest Request,
    StoredMission? Mission,
    IReadOnlyList<MissionLogEntry> Log);

/// <summary>
/// A typed permission decision carrying both the outcome and the reason, so a PS
/// can act on it and display it (§Permission Endpoint).
/// </summary>
/// <param name="Outcome">Grant, deny, or prompt.</param>
/// <param name="Reason">Why the decision was reached.</param>
/// <param name="Message">Optional Markdown message for the user (e.g. a denial reason).</param>
public sealed record PermissionDecision(
    PermissionOutcome Outcome,
    PermissionDecisionReason Reason,
    string? Message = null);

/// <summary>
/// PS-side policy seam for the permission endpoint (§Permission Endpoint). The
/// SDK supplies the inputs (<see cref="PermissionDecisionContext"/>) and the
/// reason enum; the PS implements the policy.
/// </summary>
public interface IPermissionDecider
{
    /// <summary>Decide a permission request given its mission + log context.</summary>
    Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, CancellationToken ct = default);
}
