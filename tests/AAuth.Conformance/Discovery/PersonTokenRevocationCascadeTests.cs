using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AAuth.Server;
using Xunit;
using static AAuth.Conformance.Discovery.RevocationLifecycleTests;

namespace AAuth.Conformance.Discovery;

public class PersonTokenRevocationCascadeTests
{
    private const string Person = RevocationLifecycleTests.Person;
    private const string Access = RevocationLifecycleTests.Access;

    [Fact(DisplayName = "§Revocation Cascade — a PS revoking its person token revokes it at its aud and at every AS it was presented to")]
    public async Task RevokeToken_ReachesAudienceAndEveryAccessServer()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "agent");
        var person = await graph.IssuePersonTokenAsync(agent, FirstResource);
        var grant = await graph.GrantAsync(agent, FirstResource, federated: true, personToken: person);
        Assert.Equal(HttpStatusCode.OK, await graph.UseAsync(grant, FirstResource));
        var personJti = (string)Decode(person)["jti"]!;

        var result = await graph.PersonRevocation.RevokeTokenAsync(personJti);

        Assert.Null(Assert.Single(result.Downstream, entry => entry.Recipient == FirstResource).Error);
        var accessServer = Assert.Single(result.Downstream, entry => entry.Recipient == Access);
        Assert.Null(accessServer.Error);
        // The AS reports its own cascade: the auth token it issued against the person token.
        Assert.Null(Assert.Single(accessServer.Downstream).Error);
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource && entry.Token == new TokenKey(Person, personJti));
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(Access, (string)Decode(grant)["jti"]!));
        Assert.Equal(HttpStatusCode.Unauthorized, await graph.UseAsync(grant, FirstResource));

        // Idempotent per (iss, jti): the repeat records nothing new and reports the same recipients.
        var repeated = await graph.PersonRevocation.RevokeTokenAsync(personJti);
        Assert.Equal(result.Downstream.Select(entry => entry.Recipient).Order(), repeated.Downstream.Select(entry => entry.Recipient).Order());
        Assert.All(repeated.Downstream, entry => Assert.Null(entry.Error));
    }

    [Fact(DisplayName = "§Revocation Cascade — person tokens issued from an auth token against the revoked person token are revoked")]
    public async Task RevokeToken_RevokesUpstreamDerivedPersonTokens()
    {
        await using var graph = await Graph.CreateAsync();
        var caller = await graph.AgentTokenAsync(FirstProvider, "caller");
        var intermediary = await graph.AgentTokenAsync(FirstResource, "intermediary", distinctKey: true);
        var person = await graph.IssuePersonTokenAsync(caller, FirstResource);
        var upstream = await graph.GrantAsync(caller, FirstResource, federated: false, personToken: person);
        var derived = await graph.IssueChainedPersonTokenAsync(intermediary, SecondResource, upstream);

        var result = await graph.PersonRevocation.RevokeTokenAsync((string)Decode(person)["jti"]!);

        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource
            && entry.Token == new TokenKey(Person, (string)Decode(upstream)["jti"]!));
        Assert.Contains(graph.Revocations, entry => entry.Resource == SecondResource
            && entry.Token == new TokenKey(Person, (string)Decode(derived)["jti"]!));
        Assert.Contains(result.Downstream, entry => entry.Recipient == SecondResource && entry.Error is null);
    }

    [Fact(DisplayName = "§Token Revocation — revoking a token with no record reports nothing and does not throw")]
    public async Task RevokeToken_UnknownJti_ReportsNothing()
    {
        await using var graph = await Graph.CreateAsync();

        var result = await graph.PersonRevocation.RevokeTokenAsync("never-issued");

        Assert.Empty(result.Downstream);
    }
}
