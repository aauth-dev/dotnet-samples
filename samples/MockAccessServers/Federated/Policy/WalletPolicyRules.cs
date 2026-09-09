using System.Security.Cryptography;
using System.Text;
using AAuth.Access;
using Microsoft.IdentityModel.Tokens;

namespace MockAccessServer.Policy;

public sealed class WalletPolicyRules(string wallet, string concierge)
{
    public const string ReviewScope = "wallet.review";

    public AccessDecision? Evaluate(AccessPolicyRequest request)
    {
        if (request.ResourceUrl == wallet && request.Scope == ReviewScope && request.ClarificationHistory.Count == 0)
            return AccessDecision.NeedsClarification("Why is a wallet review needed for this trip?", 120);
        if (request.PersonServerIssuer is not null) return null;
        if (request.UpstreamAuthorization is not { IsValid: true, Mission: null } upstream) return null;
        if (request.ResourceUrl != wallet || request.Scope != "wallet.read"
            || upstream.Scope != "wallet.read"
            || (string?)upstream.Verified?.Payload["aud"] != concierge)
            return AccessDecision.Deny("The upstream grant does not authorize this wallet delegation.");
        var subject = upstream.Subject is null ? null : Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(
            "wallet-delegation\n" + upstream.Subject + "\n" + wallet)));
        return AccessDecision.Allow(subject);
    }
}