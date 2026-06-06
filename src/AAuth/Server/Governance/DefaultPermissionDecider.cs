using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IPermissionDecider"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own policy. It grants a
/// request only when the action is a pre-approved tool on the bound mission
/// (§Permission Endpoint — pre-approved tools resolve without prompting);
/// every other action is left to the user via <see cref="PermissionOutcome.Prompt"/>.
/// A real PS should override this with its own policy.
/// </summary>
public sealed class DefaultPermissionDecider : IPermissionDecider
{
    /// <inheritdoc />
    public Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, CancellationToken ct = default)
    {
        System.ArgumentNullException.ThrowIfNull(context);

        if (context.Mission is not null)
        {
            var mission = Mission.FromApprovalBytes(context.Mission.Blob.Span);
            foreach (var tool in mission.ApprovedTools)
            {
                if (string.Equals(tool.Name, context.Request.Action.Name, System.StringComparison.Ordinal))
                {
                    return Task.FromResult(new PermissionDecision(
                        PermissionOutcome.Granted, PermissionDecisionReason.ApprovedTool));
                }
            }
        }

        return Task.FromResult(new PermissionDecision(
            PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope));
    }
}
