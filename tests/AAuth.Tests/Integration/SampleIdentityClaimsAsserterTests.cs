using System.Collections.Generic;
using System.Threading.Tasks;
using AAuth.Person;
using MockPersonServer;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// SMP-01 negative control: the demo "admin" roles are granted on an exact agent
/// identifier, never on a prefix an arbitrary agent provider could mint.
/// </summary>
public class SampleIdentityClaimsAsserterTests
{
    [Theory]
    [InlineData("aauth:demo@ap.example", true)]
    [InlineData("aauth:demo@attacker.example", false)]
    [InlineData("aauth:demo@ap.example.attacker.example", false)]
    [InlineData("aauth:demo-evil@ap.example", false)]
    public async Task AdminRoles_RequireExactAgentIdentifier(string agentId, bool admin)
    {
        var asserter = new SampleIdentityClaimsAsserter(new ConsentStore(), requireConsent: false,
            demoRoles: ["calendar.owner"], demoGroups: ["demo-users"],
            demoUserClaims: new Dictionary<string, string>());

        var assertion = await asserter.AssertAsync(new IdentityAssertionRequest
        {
            ResourceUrl = "https://calendar.example",
            Scope = "calendar.read",
            AgentId = agentId,
        });

        Assert.Equal(IdentityAssertionKind.Assert, assertion.Kind);
        Assert.Equal(admin, assertion.Roles is not null);
        Assert.Equal(admin, assertion.Groups is not null);
    }
}
