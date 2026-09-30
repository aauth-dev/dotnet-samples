using AAuth.Agent;
using AAuth.Crypto;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Conformance.Agents;

/// <summary>Missions, clarification and call chaining, each through the DI path (<c>AddAAuthAgent</c>).</summary>
public class AgentDependencyInjectionFlowTests
{
    private const string AgentId = "aauth:planner@agent.test";

    [Fact(DisplayName = "§Missions — a DI agent configured with its mission requests mission-scoped tokens")]
    public async Task DiAgent_WithMission_IssuesMissionScopedAuthToken()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        await host.SaveMissionAsync(AgentId);
        await using var provider = await AgentAsync(host, key, options => options.Mission = host.ApprovedMission(AgentId));

        var auth = await provider.GetRequiredService<IAAuthAgentFactory>().Get("planner").HttpClient
            .GetStringAsync(host.Origin + "/data");

        Assert.Equal(AgentFlowHost.Mission, (string?)AgentFlowHost.Claims(auth)["mission_s256"]);
    }

    [Fact(DisplayName = "§Clarification Chat — a DI agent answers the PS's clarification and receives its token")]
    public async Task DiAgent_AnswersClarification()
    {
        await using var host = await AgentFlowHost.StartAsync();
        host.Consent.Clarify = true;
        var key = AAuthKey.Generate();
        await host.SaveMissionAsync(AgentId);
        string? asked = null;
        await using var provider = await AgentAsync(host, key, options =>
        {
            options.Mission = host.ApprovedMission(AgentId);
            options.Challenge.OnClarificationRequired = (clarification, _) =>
            {
                asked = clarification.Clarification;
                return Task.FromResult(ClarificationResponse.Respond("To book the venue."));
            };
        });

        var auth = await provider.GetRequiredService<IAAuthAgentFactory>().Get("planner").HttpClient
            .GetStringAsync(host.Origin + "/data");

        Assert.Equal("Why does the offsite need this?", asked);
        Assert.Equal(AgentFlowHost.Mission, (string?)AgentFlowHost.Claims(auth)["mission_s256"]);
    }

    [Fact(DisplayName = "§Call Chaining — a DI agent chains its upstream token")]
    public async Task DiAgent_ChainsUpstreamToken()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var upstream = await host.UpstreamAsync("person-a");
        await using var provider = await AgentAsync(host, key, options => options.UpstreamTokenProvider = () => upstream);

        var auth = await provider.GetRequiredService<IAAuthAgentFactory>().Get("planner").HttpClient
            .GetStringAsync(host.Origin + "/data");

        Assert.Equal("downstream-person-a", (string?)AgentFlowHost.Claims(auth)["sub"]);
    }

    private static async Task<ServiceProvider> AgentAsync(AgentFlowHost host, AAuthKey key, Action<AAuthAgentOptions> configure)
    {
        var token = await host.AgentTokenAsync(key, AgentId);
        var services = new ServiceCollection();
        services.AddAAuthAgent("planner", options =>
        {
            options.Signer = key;
            options.AgentToken = token;
            options.PersonServer = host.Origin;
            options.EgressPolicy = host.Egress;
            configure(options);
        });
        return services.BuildServiceProvider();
    }
}
