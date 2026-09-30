using AAuth;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AAuth.Conformance.Discovery;

public class LoopbackPolicyGuardTests
{
    private static readonly AAuthEgressPolicy Loopback = AAuthEgressPolicy.ForDevelopmentLoopback("http://localhost:5002");

    [Fact(DisplayName = "loopback-admitting Person Server policy fails in Production")]
    public async Task PersonServerLoopbackPolicyFailsInProduction()
    {
        var builder = ProductionBuilder();
        builder.Services.AddAAuthPersonServer(configure: options =>
        {
            options.Issuer = "http://localhost:5002";
            options.EgressPolicy = Loopback;
            options.SigningKeys.Add("k1", AAuthKey.Generate());
        });
        await using var app = builder.Build();

        await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
    }

    [Fact(DisplayName = "loopback-admitting Access Server policy fails in Production")]
    public async Task AccessServerLoopbackPolicyFailsInProduction()
    {
        var builder = ProductionBuilder();
        builder.Services.AddSingleton<IAccessPolicy, AllowPolicy>();
        builder.Services.AddAAuthAccessServer(configure: options =>
        {
            options.Issuer = "http://localhost:5002";
            options.EgressPolicy = Loopback;
            options.SigningKeys.Add("k1", AAuthKey.Generate());
        });
        await using var app = builder.Build();

        await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
    }

    [Fact(DisplayName = "loopback-admitting Resource policy fails in Production")]
    public void ResourceLoopbackPolicyFailsInProduction()
    {
        var builder = ProductionBuilder();
        builder.Services.AddAAuthResource(options =>
        {
            options.Issuer = "http://localhost:5002";
            options.EgressPolicy = Loopback;
            options.SigningKeys.Add("k1", AAuthKey.Generate());
        });
        using var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.MapAAuthResource());
    }

    [Fact(DisplayName = "loopback-admitting Agent policy fails in Production")]
    public async Task AgentLoopbackPolicyFailsInProduction()
    {
        var builder = ProductionBuilder();
        builder.Services.AddAAuthAgent("agent", options =>
        {
            options.Signer = AAuthKey.Generate();
            options.EgressPolicy = Loopback;
            options.SelfIssued.Issuer = "http://localhost:5002";
            options.SelfIssued.Subject = "aauth:agent@localhost";
        });
        await using var app = builder.Build();

        await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
    }

    [Fact(DisplayName = "loopback-admitting Discovery policy fails when resolved in Production")]
    public void DiscoveryLoopbackPolicyFailsInProduction()
    {
        var builder = ProductionBuilder();
        builder.Services.AddAAuthDiscovery(options => options.EgressPolicy = Loopback);
        using var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.Services.GetRequiredService<MetadataClient>());
    }

    private static WebApplicationBuilder ProductionBuilder()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Production,
        });
        builder.WebHost.UseTestServer();
        return builder;
    }

    private sealed class AllowPolicy : IAccessPolicy
    {
        public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(AccessDecision.Allow());
    }
}
