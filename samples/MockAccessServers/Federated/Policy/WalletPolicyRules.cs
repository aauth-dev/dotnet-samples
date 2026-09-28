using AAuth.Access;

namespace MockAccessServer.Policy;

public sealed class WalletPolicyRules(string wallet, string concierge)
{
    public const string ReviewScope = "wallet.review";

    public AccessDecision? Evaluate(AccessPolicyRequest request)
    {
        if (request.ResourceUrl == wallet && request.Scope == ReviewScope && request.ClarificationHistory.Count == 0)
            return AccessDecision.NeedsClarification("Why is a wallet review needed for this trip?", 120);
        // Call chaining (§Call Chaining): the Concierge presents the traveller's
        // upstream token through the traveller's PS. The wallet grant is limited to
        // wallet.read delegated from a Concierge that was itself granted wallet.read.
        if (request.UpstreamAuthorization is not { IsValid: true } upstream) return null;
        // Other intermediaries (e.g. a federated worker's provider) use normal policy.
        if (upstream.Audience is not null && upstream.Audience != concierge) return null;
        if (request.ResourceUrl != wallet || request.Scope != "wallet.read"
            || upstream.Audience != concierge
            || (upstream.Scope is not null && upstream.Scope != "wallet.read"))
            return AccessDecision.Deny("The upstream grant does not authorize this wallet delegation.");
        return AccessDecision.Allow();
    }
}
