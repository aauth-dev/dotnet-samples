using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Server;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Conformance.Agents;

/// <summary>Typed clients, the token cache and client lifetime on the DI path (<c>AddAAuthAgent</c>).</summary>
public class AgentTypedClientTests
{
    private const string AgentId = "aauth:planner@agent.test";

    [Fact(DisplayName = "AddAAuthAgent — clients resolved separately share the agent's token cache")]
    public async Task DiAgent_ReusesCacheAcrossResolves()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        await using var provider = await AgentAsync(host, key);
        var clients = provider.GetRequiredService<IHttpClientFactory>();

        var obtained = await clients.CreateClient("planner").GetStringAsync(host.Origin + "/data");
        var reused = await clients.CreateClient("planner").GetStringAsync(host.Origin + "/data");
        var viaFactory = await provider.GetRequiredService<IAAuthAgentFactory>().Get("planner").HttpClient
            .GetStringAsync(host.Origin + "/data");

        Assert.Equal(obtained, reused);
        Assert.Equal(obtained, viaFactory);
        Assert.Equal(2, host.PersonServerPosts);
    }

    [Fact(DisplayName = "AddAAuthAgent — two agents configured with one TokenCache share its entries")]
    public async Task DiAgents_ShareAConfiguredCache()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var token = await host.AgentTokenAsync(key, AgentId);
        var cache = new InMemoryAAuthTokenCache();
        var services = new ServiceCollection();
        foreach (var name in new[] { "first", "second" })
            services.AddAAuthAgent(name, options =>
            {
                options.Signer = key;
                options.AgentToken = token;
                options.PersonServer = host.Origin;
                options.EgressPolicy = host.Egress;
                options.TokenCache = cache;
            });
        await using var provider = services.BuildServiceProvider();
        var clients = provider.GetRequiredService<IHttpClientFactory>();

        var obtained = await clients.CreateClient("first").GetStringAsync(host.Origin + "/data");
        var reused = await clients.CreateClient("second").GetStringAsync(host.Origin + "/data");

        Assert.Equal(obtained, reused);
        Assert.Equal(2, host.PersonServerPosts);
    }

    [Fact(DisplayName = "AddAAuthAgent — typed Person Server clients are keyed by agent name and signed as the agent")]
    public async Task DiAgent_RegistersKeyedTypedClients()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        await using var provider = await AgentAsync(host, key);
        var agent = provider.GetRequiredService<IAAuthAgentFactory>().Get("planner");

        var exchange = provider.GetRequiredKeyedService<TokenExchangeClient>("planner");
        var governance = provider.GetRequiredKeyedService<AAuthGovernanceClient>("planner");
        Assert.Same(exchange, agent.TokenExchange);
        Assert.Same(governance, agent.Governance);
        Assert.Same(provider.GetRequiredKeyedService<RevocationClient>("planner"), agent.Revocation);
        Assert.Same(governance.Mission, provider.GetRequiredKeyedService<MissionClient>("planner"));
        Assert.Same(governance.Permission, provider.GetRequiredKeyedService<PermissionClient>("planner"));
        Assert.Same(governance.Audit, provider.GetRequiredKeyedService<AuditClient>("planner"));
        Assert.Same(governance.Interaction, provider.GetRequiredKeyedService<InteractionClient>("planner"));
        Assert.Equal(host.Origin, governance.PersonServer);

        var person = AgentFlowHost.Claims(await exchange.RequestPersonTokenAsync(host.Origin, host.Origin));
        Assert.Equal(key.ComputeJwkThumbprint(),
            AAuth.Crypto.KeyFactory.FromPublicJwk((System.Text.Json.Nodes.JsonObject)person["cnf"]!["jwk"]!).ComputeJwkThumbprint());
        Assert.Null(provider.GetKeyedService<TokenExchangeClient>("other"));
    }

    [Fact(DisplayName = "AddAAuthAgent — governance clients require the agent's Person Server")]
    public async Task DiAgent_WithoutPersonServer_GovernanceThrowsClearly()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        await using var provider = await AgentAsync(host, key, options => options.PersonServer = null);

        var error = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredKeyedService<MissionClient>("planner"));
        Assert.Contains("PersonServer", error.Message);
    }

    [Fact(DisplayName = "IAAuthAgentFactory — a created agent exposes and owns its typed clients")]
    public async Task CreatedAgent_ExposesTypedClients()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var services = new ServiceCollection();
        services.AddAAuthAgentFactory();
        await using var provider = services.BuildServiceProvider();
        using var agent = provider.GetRequiredService<IAAuthAgentFactory>().Create(new AAuthAgentDescriptor("tenant")
        {
            Signer = key, AgentToken = await host.AgentTokenAsync(key, AgentId), PersonServer = host.Origin,
            EgressPolicy = host.Egress,
        });

        var person = await agent.TokenExchange.RequestPersonTokenAsync(host.Origin, host.Origin);

        Assert.Equal(host.Origin, (string?)AgentFlowHost.Claims(person)["iss"]);
        Assert.Equal(host.Origin, agent.Governance.PersonServer);
        Assert.Same(agent.TokenExchange, agent.TokenExchange);
    }

    [Fact(DisplayName = "F-C7 — a slow consent outlasts a short HttpClient.Timeout; the DI agent client is not cut off")]
    public async Task SlowConsent_IsGovernedByPollingTimeout_NotHttpClientTimeout()
    {
        await using var host = await AgentFlowHost.StartAsync();
        host.Consent.Delay = TimeSpan.FromSeconds(1.5);
        await host.SaveMissionAsync(AgentId);
        var key = AAuthKey.Generate();

        // Reproduction: the same pipeline behind an HttpClient whose Timeout is shorter than the consent.
        await using (var bounded = await AgentAsync(host, key, options => options.Mission = host.ApprovedMission(AgentId)))
        {
            using var shortTimeout = new HttpClient(
                bounded.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler("planner"), disposeHandler: false)
            { Timeout = TimeSpan.FromMilliseconds(500) };
            await Assert.ThrowsAnyAsync<TaskCanceledException>(() => shortTimeout.GetStringAsync(host.Origin + "/data"));
        }

        await using var provider = await AgentAsync(host, key, options => options.Mission = host.ApprovedMission(AgentId));
        var agent = provider.GetRequiredService<IAAuthAgentFactory>().Get("planner").HttpClient;
        Assert.Equal(Timeout.InfiniteTimeSpan, agent.Timeout);

        var auth = await agent.GetStringAsync(host.Origin + "/data");

        Assert.Equal(AgentFlowHost.Mission, (string?)AgentFlowHost.Claims(auth)["mission_s256"]);
    }

    private static async Task<ServiceProvider> AgentAsync(AgentFlowHost host, AAuthKey key,
        Action<AAuthAgentOptions>? configure = null)
    {
        var token = await host.AgentTokenAsync(key, AgentId);
        var services = new ServiceCollection();
        services.AddAAuthAgent("planner", options =>
        {
            options.Signer = key;
            options.AgentToken = token;
            options.PersonServer = host.Origin;
            options.EgressPolicy = host.Egress;
            configure?.Invoke(options);
        });
        return services.BuildServiceProvider();
    }
}
