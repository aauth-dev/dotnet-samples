using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Governance;

/// <summary>
/// Default <see cref="IMissionTokenConsent"/> used when a PS registers
/// <c>AddAAuthGovernance</c> without supplying its own out-of-scope policy. It
/// cannot know the user's intent, so it never grants or denies on its own:
/// every out-of-scope mission token request is held for an interactive review
/// (<see cref="MissionTokenConsentKind.Interact"/>), resolved out-of-band when the
/// PS's user channel marks the pending decision allowed or denied. A PS that can
/// decide (a consent screen, a scripted test, or an LLM reviewer) overrides this.
/// </summary>
public sealed class DefaultMissionTokenConsent : IMissionTokenConsent
{
    /// <inheritdoc />
    public Task<MissionTokenConsentDecision> ReviewAsync(
        MissionTokenConsentContext context, CancellationToken cancellationToken = default)
    {
        System.ArgumentNullException.ThrowIfNull(context);
        return Task.FromResult(MissionTokenConsentDecision.Interact());
    }
}
