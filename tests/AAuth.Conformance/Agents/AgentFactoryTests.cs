using System.Net;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AAuth.Conformance.Agents;

public class AgentFactoryTests
{
    [Fact(DisplayName = "IAAuthAgentFactory — tenant agents with different keys and Person Servers stay isolated")]
    public async Task TenantAgents_StayIsolated()
    {
        await using var first = await AgentFlowHost.StartAsync();
        await using var second = await AgentFlowHost.StartAsync();
        var egress = AAuthEgressPolicy.ForDevelopmentLoopback(first.Origin, second.Origin);
        var firstKey = AAuthKey.Generate();
        var secondKey = AAuthKey.Generate();
        var services = new ServiceCollection();
        services.AddAAuthAgentFactory();
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IAAuthAgentFactory>();

        using var tenantA = factory.Create(new AAuthAgentDescriptor("tenant-a")
        {
            Signer = firstKey, AgentToken = await first.AgentTokenAsync(firstKey, "aauth:tenant-a@agent.test"),
            PersonServer = first.Origin, EgressPolicy = egress,
        });
        using var tenantB = factory.Create(new AAuthAgentDescriptor("tenant-b")
        {
            Signer = secondKey, AgentToken = await second.AgentTokenAsync(secondKey, "aauth:tenant-b@agent.test"),
            PersonServer = second.Origin, EgressPolicy = egress,
        });

        var authA = AgentFlowHost.Claims(await tenantA.HttpClient.GetStringAsync(first.Origin + "/data"));
        var authB = AgentFlowHost.Claims(await tenantB.HttpClient.GetStringAsync(second.Origin + "/data"));

        Assert.Equal(first.Origin, (string?)authA["iss"]);
        Assert.Equal(second.Origin, (string?)authB["iss"]);
        Assert.Equal(firstKey.ComputeJwkThumbprint(), Thumbprint(authA));
        Assert.Equal(secondKey.ComputeJwkThumbprint(), Thumbprint(authB));
    }

    [Fact(DisplayName = "IAAuthAgentFactory — a per-request intermediary agent chains its own upstream token")]
    public async Task PerRequestIntermediary_ChainsItsOwnUpstream()
    {
        await using var host = await AgentFlowHost.StartAsync();
        var key = AAuthKey.Generate();
        var token = await host.AgentTokenAsync(key, "aauth:intermediary@agent.test");
        var services = new ServiceCollection();
        services.AddAAuthAgentFactory();
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IAAuthAgentFactory>();

        foreach (var person in new[] { "person-a", "person-b" })
        {
            var upstream = await host.UpstreamAsync(person);
            using var agent = factory.Create(new AAuthAgentDescriptor("request-" + person)
            {
                Signer = key, AgentToken = token, EgressPolicy = host.Egress, UpstreamTokenProvider = () => upstream,
            });

            var auth = AgentFlowHost.Claims(await agent.HttpClient.GetStringAsync(host.Origin + "/data"));

            Assert.Equal("downstream-" + person, (string?)auth["sub"]);
        }
    }

    [Fact(DisplayName = "IAAuthAgentFactory — the factory owns registered agents; the caller owns created ones")]
    public async Task DisposalOwnership()
    {
        var key = AAuthKey.Generate();
        var token = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = "https://ap.example", Subject = "aauth:owned@ap.example",
            Key = key, KeyId = "key", ConfirmationKey = key,
        }.BuildAsync();
        void Configure(AAuthAgentOptions options)
        {
            options.Signer = key;
            options.AgentToken = token;
            options.EgressPolicy = TestEgress.Policy;
            options.InnerHandler = new OkHandler();
            options.TransportContract = AAuthTransportContract.InProcessOnly;
        }
        var services = new ServiceCollection();
        services.AddAAuthAgent("registered", Configure);
        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IAAuthAgentFactory>();

        var registered = factory.Get("registered");
        Assert.Same(registered, factory.Get("registered"));
        registered.Dispose();
        Assert.Equal(HttpStatusCode.OK, (await registered.HttpClient.GetAsync("https://resource.example/")).StatusCode);

        var created = factory.Create(Describe("created", Configure));
        created.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => created.HttpClient.GetAsync("https://resource.example/"));

        Assert.Throws<InvalidOperationException>(() => factory.Get("unknown"));
        Assert.Throws<OptionsValidationException>(() => factory.Create(new AAuthAgentDescriptor("invalid") { Signer = key }));

        await provider.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => registered.HttpClient.GetAsync("https://resource.example/"));
    }

    private static AAuthAgentDescriptor Describe(string name, Action<AAuthAgentOptions> configure)
    {
        var descriptor = new AAuthAgentDescriptor(name);
        configure(descriptor);
        return descriptor;
    }

    private static string Thumbprint(JsonObject auth)
        => KeyFactory.FromPublicJwk((JsonObject)auth["cnf"]!["jwk"]!).ComputeJwkThumbprint();

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
