using AAuth.Agent;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Conformance.Agents;

/// <summary>
/// Carrier tokens live in an <see cref="IAAuthTokenCache"/> keyed by agent token, upstream, mission,
/// audience, account and key. Each full flow at a fresh resource costs two Person Server POSTs: a
/// person token request and the auth token exchange.
/// </summary>
public class TokenCacheSharingTests
{
    private const string AgentId = "aauth:planner@agent.test";

    [Fact(DisplayName = "IAAuthTokenCache — two builds sharing a cache perform one exchange")]
    public async Task TwoBuilds_SharingACache_ExchangeOnce()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var token = await host.AgentTokenAsync(key, AgentId);
        var cache = new InMemoryAAuthTokenCache();
        using var first = Build(host, key, token, cache);
        using var second = Build(host, key, token, cache);

        var obtained = await first.GetStringAsync(host.Origin + "/data");
        Assert.Equal(2, host.PersonServerPosts);
        var reused = await second.GetStringAsync(host.Origin + "/data");

        Assert.Equal(obtained, reused);
        Assert.Equal(2, host.PersonServerPosts);
    }

    [Fact(DisplayName = "IAAuthTokenCache — alternating two resources exchanges once per resource, not once per call")]
    public async Task AlternatingResources_ExchangeOncePerResource()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        using var client = Build(host, key, await host.AgentTokenAsync(key, AgentId), new InMemoryAAuthTokenCache());

        for (var i = 0; i < 3; i++)
        {
            var first = AgentFlowHost.Claims(await client.GetStringAsync(host.Origin + "/data"));
            var second = AgentFlowHost.Claims(await client.GetStringAsync(host.SecondOrigin + "/data"));
            Assert.Equal(host.Origin, (string?)first["aud"]);
            Assert.Equal(host.SecondOrigin, (string?)second["aud"]);
        }

        Assert.Equal(4, host.PersonServerPosts);
    }

    [Fact(DisplayName = "IAAuthTokenCache — concurrent first requests share one exchange")]
    public async Task ConcurrentFirstRequests_ShareOneExchange()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        using var client = Build(host, key, await host.AgentTokenAsync(key, AgentId), new InMemoryAAuthTokenCache());
        var hold = host.HoldPersonServer();

        // Every request is refused and reaches the exchange while the Person Server is held.
        var requests = Enumerable.Range(0, 8).Select(_ => client.GetStringAsync(host.Origin + "/data")).ToArray();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (host.DataRequests < requests.Length && DateTime.UtcNow < deadline) await Task.Delay(10);
        await Task.Delay(200);
        hold.SetResult();
        var tokens = await Task.WhenAll(requests);

        Assert.Single(tokens.Distinct());
        Assert.Equal(2, host.PersonServerPosts);
    }

    [Fact(DisplayName = "IAAuthTokenCache — a different upstream token never reuses another person's entry")]
    public async Task DifferentUpstream_NeverReuses()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var upstreamA = await host.UpstreamAsync("person-a");
        var upstreamB = await host.UpstreamAsync("person-b");
        var upstream = upstreamA;
        using var client = new AAuthClientBuilder(key).UseJwt(await host.AgentTokenAsync(key, AgentId))
            .WithEgressPolicy(host.Egress).WithCallChaining(() => upstream)
            .WithTokenCache(new InMemoryAAuthTokenCache()).Build();

        var first = AgentFlowHost.Claims(await client.GetStringAsync(host.Origin + "/data"));
        var posts = host.PersonServerPosts;
        upstream = upstreamB;
        var second = AgentFlowHost.Claims(await client.GetStringAsync(host.Origin + "/data"));

        Assert.Equal("downstream-person-a", (string?)first["sub"]);
        Assert.Equal("downstream-person-b", (string?)second["sub"]);
        Assert.True(host.PersonServerPosts > posts);
    }

    [Fact(DisplayName = "IAAuthTokenCache — a mission request never reuses a mission-less entry")]
    public async Task DifferentMission_NeverReuses()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var token = await host.AgentTokenAsync(key, AgentId);
        await host.SaveMissionAsync(AgentId);
        var cache = new InMemoryAAuthTokenCache();
        using var plain = Build(host, key, token, cache);
        using var missionBound = new AAuthClientBuilder(key).UseJwt(token).WithEgressPolicy(host.Egress)
            .WithChallengeHandling(host.Origin).WithMission(host.ApprovedMission(AgentId)).WithTokenCache(cache).Build();

        var withoutMission = AgentFlowHost.Claims(await plain.GetStringAsync(host.Origin + "/data"));
        var withMission = AgentFlowHost.Claims(await missionBound.GetStringAsync(host.Origin + "/data"));

        Assert.Null((string?)withoutMission["mission_s256"]);
        Assert.Equal(AgentFlowHost.Mission, (string?)withMission["mission_s256"]);
        Assert.Equal(4, host.PersonServerPosts);
    }

    private static HttpClient Build(AgentFlowHost host, AAuthKey key, string token, IAAuthTokenCache cache)
        => new AAuthClientBuilder(key).UseJwt(token).WithEgressPolicy(host.Egress)
            .WithChallengeHandling(host.Origin).WithTokenCache(cache).Build();
}
