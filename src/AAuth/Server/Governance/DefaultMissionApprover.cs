using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IMissionApprover"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own approver. It approves every
/// proposed mission and every proposed tool (§Mission Creation). A real PS should
/// override this to surface the proposal to the user and prune the approved tools.
/// </summary>
public sealed class DefaultMissionApprover : IMissionApprover
{
    /// <inheritdoc />
    public Task<MissionApprovalDecision> ApproveAsync(MissionApprovalContext context, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(context);
        return Task.FromResult(MissionApprovalDecision.Approve(context.Proposal.Tools));
    }
}
