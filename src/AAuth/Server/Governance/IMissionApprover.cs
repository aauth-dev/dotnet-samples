using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>The PS's outcome for a mission proposal (§Mission Creation).</summary>
public enum MissionApprovalOutcome
{
    /// <summary>Approve the mission without prompting the user.</summary>
    Approved,

    /// <summary>Decline the mission without prompting the user.</summary>
    Declined,

    /// <summary>
    /// Defer — the PS must prompt the user before approving. The mapper parks the
    /// proposal via <see cref="IDeferredConsentStore"/> and answers <c>202</c>.
    /// </summary>
    Prompt,
}

/// <summary>
/// The inputs a PS evaluates when deciding a mission proposal: the proposing
/// agent, the approving PS, and the proposal itself (§Mission Creation).
/// </summary>
/// <param name="Agent">The agent identifier the mission would be approved for.</param>
/// <param name="Approver">HTTPS URL of the approver (the PS).</param>
/// <param name="Proposal">The parsed mission proposal.</param>
public sealed record MissionApprovalContext(
    string Agent,
    string Approver,
    MissionProposal Proposal);

/// <summary>
/// A typed mission-approval decision carrying the outcome and — when approved —
/// the subset of proposed tools the PS approved (§Mission Approval). A real PS
/// may prune the proposed tools; the approved set is what gets written into the
/// verbatim approval blob.
/// </summary>
/// <param name="Outcome">Approve, decline, or prompt.</param>
/// <param name="ApprovedTools">The approved tools (used only when <see cref="Outcome"/> is approved).</param>
/// <param name="Message">Optional Markdown message for the user (e.g. a decline reason).</param>
public sealed record MissionApprovalDecision(
    MissionApprovalOutcome Outcome,
    IReadOnlyList<MissionTool> ApprovedTools,
    string? Message = null)
{
    /// <summary>Approve the mission with the given approved tool set.</summary>
    public static MissionApprovalDecision Approve(IReadOnlyList<MissionTool> approvedTools)
        => new(MissionApprovalOutcome.Approved, approvedTools);

    /// <summary>Decline the mission, optionally with a user-facing message.</summary>
    public static MissionApprovalDecision Decline(string? message = null)
        => new(MissionApprovalOutcome.Declined, System.Array.Empty<MissionTool>(), message);

    /// <summary>Defer to the user via the deferred-consent (202) flow.</summary>
    public static MissionApprovalDecision Defer()
        => new(MissionApprovalOutcome.Prompt, System.Array.Empty<MissionTool>());
}

/// <summary>
/// PS-side policy seam for mission creation (§Mission Creation, §Mission
/// Approval). The SDK supplies the proposal context and the approval-blob builder
/// (<see cref="MissionApprovalBuilder"/>); the PS decides whether to approve, and
/// which proposed tools to approve. The default
/// (<see cref="DefaultMissionApprover"/>) approves every proposed tool.
/// </summary>
public interface IMissionApprover
{
    /// <summary>Decide a mission proposal.</summary>
    Task<MissionApprovalDecision> ApproveAsync(MissionApprovalContext context, CancellationToken ct = default);
}
