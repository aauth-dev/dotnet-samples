using System.Threading;
using System.Threading.Tasks;
using AAuth.Server.Governance;

namespace MockPersonServer;

/// <summary>
/// The MockPS out-of-scope mission decision — the SDK's
/// <see cref="IMissionTokenConsent"/> seam. The SDK owns the protocol (the
/// <c>requirement=clarification</c> round-trip, the deferred 202/poll, the
/// mission log); this scripted policy stands in for a live user-consent screen
/// (a production PS — or an LLM-driven reviewer — replaces it).
/// </summary>
/// <remarks>
/// Maps the deterministic <see cref="MissionConsentScript"/> onto the seam:
/// <list type="bullet">
/// <item>in-scope (per <see cref="MissionPolicyStore"/>) ⇒ <c>Grant</c> (silent, gate 2a);</item>
/// <item>out-of-scope with <see cref="MissionConsentScript.RequireTokenClarification"/>
/// ⇒ <c>Clarify</c> the scripted question once;</item>
/// <item>out-of-scope otherwise ⇒ <c>Interact</c> (prompt), then the poll resolves
/// to <c>Grant</c>/<c>Deny</c> per <see cref="MissionConsentScript.ApproveOutOfScopeToken"/>;</item>
/// <item>in <see cref="MissionConsentScript.InteractiveBrowser"/> mode the poll stays
/// <c>Interact</c> until the browser marks the pending decision.</item>
/// </list>
/// </remarks>
public sealed class ScriptMissionTokenConsent : IMissionTokenConsent
{
    private readonly MissionPolicyStore _policy;
    private readonly MissionConsentScript _script;

    public ScriptMissionTokenConsent(MissionPolicyStore policy, MissionConsentScript script)
    {
        _policy = policy;
        _script = script;
    }

    public Task<MissionTokenConsentDecision> ReviewAsync(
        MissionTokenConsentContext context, CancellationToken cancellationToken = default)
    {
        if (context.Stage == MissionTokenConsentStage.Gate)
        {
            // Gate 2a: within the approved intent → silent grant.
            if (_policy.IsInScope(context.Mission.S256, context.ResourceUrl, context.Scope))
            {
                return Task.FromResult(MissionTokenConsentDecision.Grant());
            }
            // Gate 2c: out of scope → a clarification round first, else prompt.
            if (_script.RequireTokenClarification)
            {
                return Task.FromResult(MissionTokenConsentDecision.Clarify(_script.ClarificationQuestion));
            }
            return Task.FromResult(MissionTokenConsentDecision.Interact());
        }

        // Resolve (poll): interactive mode holds for a browser decision; the
        // scripted mode resolves immediately.
        if (_script.InteractiveBrowser)
        {
            return Task.FromResult(MissionTokenConsentDecision.Interact());
        }
        return Task.FromResult(_script.ApproveOutOfScopeToken
            ? MissionTokenConsentDecision.Grant()
            : MissionTokenConsentDecision.Deny("the user denied this request"));
    }
}
