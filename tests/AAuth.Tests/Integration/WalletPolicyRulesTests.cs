using AAuth.Access;
using AAuth.Tokens;
using MockAccessServer.Policy;
using Xunit;

namespace AAuth.Tests.Integration;

public class WalletPolicyRulesTests
{
    private readonly WalletPolicyRules _rules = new("http://localhost:5003", "http://localhost:5200");

    [Fact]
    public void Review_RequiresClarificationBeforeNormalPolicy()
    {
        var request = new AccessPolicyRequest
        {
            ResourceUrl = "http://localhost:5003", Scope = "wallet.review", AgentId = "aauth:demo@ap.example",
        };
        Assert.Equal(AccessDecisionKind.NeedsClarification, _rules.Evaluate(request)!.Kind);
        Assert.Null(_rules.Evaluate(new AccessPolicyRequest
        {
            ResourceUrl = request.ResourceUrl, Scope = request.Scope, AgentId = request.AgentId,
            ClarificationHistory = ["Compare trip expenses"],
        }));
    }

    [Fact]
    public void FederatedWorkerDelegationContinuesThroughNormalPolicy()
    {
        Assert.Null(_rules.Evaluate(new AccessPolicyRequest
        {
            ResourceUrl = "http://localhost:5003", Scope = "wallet.read", AgentId = "aauth:parent+worker@ap.example",
            PersonServerIssuer = "http://localhost:5100",
            UpstreamAuthorization = new UpstreamTokenValidationResult { IsValid = true, Scope = "delegation.invoke" },
        }));
    }

    [Theory]
    [InlineData("wallet.charge")]
    [InlineData("wallet.read")]
    public void UnboundUpstreamCannotAuthorizeWallet(string scope)
    {
        var request = new AccessPolicyRequest
        {
            ResourceUrl = "http://localhost:5003", Scope = scope, AgentId = "aauth:concierge@localhost:5200",
            UpstreamAuthorization = new UpstreamTokenValidationResult { IsValid = true, Scope = "wallet.read", Subject = "person" },
        };
        Assert.Equal(AccessDecisionKind.Deny, _rules.Evaluate(request)!.Kind);
    }
}