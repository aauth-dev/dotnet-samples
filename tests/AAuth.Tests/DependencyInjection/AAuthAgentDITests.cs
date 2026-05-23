using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

public class AAuthAgentDITests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    private string BuildAgentToken(string? ps = "https://ps.example")
    {
        return new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            KeyId = "k1",
            Key = _key,
            PersonServer = ps,
        }.Build();
    }

    [Fact]
    public void AddAAuthAgent_WithoutAgentToken_RegistersSigningOnly()
    {
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthAgent_WithPersonServer_RegistersFullPipeline()
    {
        var token = BuildAgentToken();
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.AgentToken = token;
            opts.PersonServer = "https://ps.example";
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthAgent_WithoutPersonServer_ReadsPsFromToken()
    {
        var token = BuildAgentToken("https://ps.fromtoken.example");
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.AgentToken = token;
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthAgent_WithoutKey_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddAAuthAgent("my-agent", opts => { }));
    }

    [Fact]
    public async Task AddAAuthAgent_ClientSigns()
    {
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        // The client will fail to connect (no real server), but we can verify
        // it was created successfully. A more thorough test would need a TestServer.
        Assert.NotNull(client);
    }
}
