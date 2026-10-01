using System.Collections.Generic;
using System.Threading.Tasks;
using AAuth.Person;
using MockPersonServer;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Roles and groups are identity claims about the person (RFC 9068 / SCIM): the demo
/// PS asserts the demo person's roles whichever agent asks, and none for a guest person.
/// </summary>
public class SampleIdentityClaimsAsserterTests
{
    [Theory]
    [InlineData("aauth:demo@ap.example", "https://ap.example")]
    [InlineData("aauth:agent-0123@localhost", "http://localhost:5301")]
    [InlineData("aauth:guest@attacker.example", "https://attacker.example")]
    public async Task Roles_BelongToThePerson_NotTheAgent(string agentId, string agentIssuer)
    {
        var asserter = new SampleIdentityClaimsAsserter(new ConsentStore(), requireConsent: false,
            demoRoles: ["calendar.owner", "wallet.payer"], demoGroups: ["demo-users"],
            demoUserClaims: new Dictionary<string, string>());

        var assertion = await asserter.AssertAsync(Request(agentId, agentIssuer));

        Assert.Equal(IdentityAssertionKind.Assert, assertion.Kind);
        Assert.Equal(["calendar.owner", "wallet.payer"], assertion.Roles);
        Assert.Equal(["demo-users"], assertion.Groups);
    }

    [Fact]
    public async Task GuestPerson_HasNoRolesOrGroups()
    {
        var asserter = new SampleIdentityClaimsAsserter(new ConsentStore(), requireConsent: false,
            demoRoles: null, demoGroups: null, demoUserClaims: new Dictionary<string, string>());

        var assertion = await asserter.AssertAsync(Request("aauth:demo@ap.example", "https://ap.example"));

        Assert.Equal(IdentityAssertionKind.Assert, assertion.Kind);
        Assert.Null(assertion.Roles);
        Assert.Null(assertion.Groups);
    }

    private static IdentityAssertionRequest Request(string agentId, string agentIssuer) => new()
    {
        ResourceUrl = "https://calendar.example",
        Scope = "calendar.read",
        AgentId = agentId,
        AgentIssuer = agentIssuer,
    };
}
