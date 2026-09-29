using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

public class AAuthAgentDITests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    private async Task<string> BuildAgentTokenAsync(string? ps = "https://ps.example")
    {
        return await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            KeyId = "k1",
            Key = _key,
            PersonServer = ps,
        }.BuildAsync();
    }

    [Fact]
    public void AddAAuthAgent_ExplicitGenericProvider_RegistersSigningOnly()
    {
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.SignatureKeyProvider = new AAuth.HttpSig.HwkSignatureKeyProvider(_key);
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthAgent_WithPersonServer_RegistersFullPipeline()
    {
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.TokenRefresher = new TestTokenRefresher();
            opts.PersonServer = "https://ps.example";
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthAgent_WithTokenRefresherAndPersonServer_RegistersFullPipeline()
    {
        var services = new ServiceCollection();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.TokenRefresher = new TestTokenRefresher();
            opts.PersonServer = "https://ps.example";
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
        var agentToken = await BuildAgentTokenAsync();
        services.AddAAuthAgent("my-agent", opts =>
        {
            opts.Key = _key;
            opts.AgentToken = agentToken;
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("my-agent");

        // The client will fail to connect (no real server), but we can verify
        // it was created successfully. A more thorough test would need a TestServer.
        Assert.NotNull(client);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AddAAuthAgent_MissingTokenSource_FailsClosed(bool resourceManaged)
    {
        var services = new ServiceCollection();
        Assert.Throws<InvalidOperationException>(() => services.AddAAuthAgent("agent", options =>
        {
            options.Key = _key;
            options.EnableResourceManagedAccess = resourceManaged;
        }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AddAAuthAgent_GenericProviderCannotSelectAuthorizationFlow(bool resourceManaged)
    {
        var services = new ServiceCollection();
        Assert.Throws<InvalidOperationException>(() => services.AddAAuthAgent("agent", options =>
        {
            options.Key = _key;
            options.SignatureKeyProvider = new AAuth.HttpSig.HwkSignatureKeyProvider(_key);
            options.EnableResourceManagedAccess = resourceManaged;
            options.PersonServer = resourceManaged ? null : "https://ps.example";
        }));
    }

    private sealed class TestTokenRefresher : ITokenRefresher
    {
        public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
            => Task.FromResult("eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoidGVzdCIsImV4cCI6OTk5OTk5OTk5OX0.fake");
    }
}
