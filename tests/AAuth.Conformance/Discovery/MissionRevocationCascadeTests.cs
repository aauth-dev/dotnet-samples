using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Server;
using AAuth.Server.Governance;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static AAuth.Conformance.Discovery.RevocationLifecycleTests;

namespace AAuth.Conformance.Discovery;

public class MissionRevocationCascadeTests
{
    private const string Person = RevocationLifecycleTests.Person;

    [Fact(DisplayName = "§Revocation Cascade — a PS revoking a mission terminates it and revokes the tokens issued under it")]
    public async Task RevokeMission_TerminatesAndRevokesMissionTokens()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "mission-agent");
        using var client = graph.AgentClient(agent);
        using var approval = await client.PostAsJsonAsync(Person + "/mission",
            new { description = "Plan the offsite", resources = new[] { FirstResource, SecondResource } });
        Assert.True(approval.StatusCode == HttpStatusCode.OK, await approval.Content.ReadAsStringAsync());
        var mission = Mission.FromApprovalResponse(await approval.Content.ReadAsByteArrayAsync(), Person);
        var outside = await graph.IssuePersonTokenAsync(agent, FirstResource);

        var result = await graph.PersonRevocation.RevokeMissionAsync(mission.S256);

        foreach (var (resource, token) in mission.PersonTokens)
        {
            Assert.Contains(graph.Revocations, entry => entry.Resource == resource
                && entry.Token == new TokenKey(Person, (string)Decode(token)["jti"]!));
            Assert.Contains(result.Downstream, entry => entry.Recipient == resource && entry.Error is null);
        }
        Assert.DoesNotContain(graph.Revocations, entry => entry.Token.TokenId == (string)Decode(outside)["jti"]!);
        var stored = await graph.PersonServices.GetRequiredService<IMissionStore>().GetAsync(mission.S256);
        Assert.Equal(MissionState.Terminated, stored!.State);

        // Subsequent token requests referencing the mission are denied.
        using var later = await client.PostAsJsonAsync(Person + "/person", new { resource = FirstResource, mission_s256 = mission.S256 });
        Assert.Equal(HttpStatusCode.Forbidden, later.StatusCode);
        Assert.Equal("mission_terminated", (string?)(await later.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }
}
