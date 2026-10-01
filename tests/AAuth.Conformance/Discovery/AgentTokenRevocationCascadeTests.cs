using System.Net;
using System.Threading.Tasks;
using AAuth.Server;
using Xunit;
using static AAuth.Conformance.Discovery.RevocationLifecycleTests;

namespace AAuth.Conformance.Discovery;

public class AgentTokenRevocationCascadeTests
{
    private const string Subject = "aauth:demo@first-ap.example";
    private const string Person = RevocationLifecycleTests.Person;
    private const string Access = RevocationLifecycleTests.Access;

    [Theory(DisplayName = "§Revocation Cascade — an agent provider's revocation cascades by sub, across the agent's agent tokens")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProviderRevoke_CascadesBySubAcrossAgentTokens(bool federated)
    {
        await using var graph = await Graph.CreateAsync();
        var first = await graph.AgentTokenAsync(FirstProvider, "first-agent-token");
        var second = await graph.AgentTokenAsync(FirstProvider, "second-agent-token");
        var other = await graph.AgentTokenAsync(SecondProvider, "other-agent-token");
        var firstPerson = await graph.IssuePersonTokenAsync(first, FirstResource);
        var secondPerson = await graph.IssuePersonTokenAsync(second, SecondResource);
        var secondGrant = await graph.GrantAsync(second, SecondResource, federated, personToken: secondPerson);
        var otherGrant = await graph.GrantAsync(other, FirstResource, federated);
        var grantIssuer = federated ? Access : Person;

        using var ap = graph.Signed(FirstProvider, "aauth-agent.json");
        var revoked = await Revoke(ap, Person, second);

        // A PS answers an agent provider with an empty 200 once its cascade is terminal.
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Empty(revoked.Downstream);
        // The person token issued under the other agent token of the same sub is revoked too.
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(Person, (string)Decode(firstPerson)["jti"]!));
        Assert.Contains(graph.Revocations, entry => entry.Resource == SecondResource
            && entry.Token == new TokenKey(grantIssuer, (string)Decode(secondGrant)["jti"]!));
        Assert.DoesNotContain(graph.Revocations, entry => entry.Token.TokenId == (string)Decode(otherGrant)["jti"]!);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(secondGrant, SecondResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(otherGrant, FirstResource));

        // The revoked agent token is refused; the binding is not altered, so the other agent token still works.
        using var blocked = await graph.RequestAsync(second, FirstResource, federated);
        Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
        using var unaffected = await graph.RequestAsync(first, FirstResource, federated);
        Assert.Equal(HttpStatusCode.OK, unaffected.StatusCode);
    }

    [Fact(DisplayName = "§Revocation Cascade — RevokeAgentAsync revokes what the PS issued to the agent without revoking its agent tokens")]
    public async Task RevokeAgent_RevokesIssuedTokensOnly()
    {
        await using var graph = await Graph.CreateAsync();
        var first = await graph.AgentTokenAsync(FirstProvider, "first-agent-token");
        var second = await graph.AgentTokenAsync(FirstProvider, "second-agent-token");
        var other = await graph.AgentTokenAsync(SecondProvider, "other-agent-token");
        var firstGrant = await graph.GrantAsync(first, FirstResource, false);
        var secondGrant = await graph.GrantAsync(second, SecondResource, false);
        var otherGrant = await graph.GrantAsync(other, FirstResource, false);

        var result = await graph.PersonRevocation.RevokeAgentAsync(FirstProvider, Subject);

        Assert.Contains(result.Downstream, entry => entry.Recipient == FirstResource && entry.Error is null);
        Assert.Contains(result.Downstream, entry => entry.Recipient == SecondResource && entry.Error is null);
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(firstGrant, FirstResource));
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(secondGrant, SecondResource));
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(otherGrant, FirstResource));
        using var fresh = await graph.RequestAsync(first, FirstResource, false);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }
}
