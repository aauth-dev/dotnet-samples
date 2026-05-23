using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthClientBuilderChallengeTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    private string BuildAgentToken(string? personServer = "https://ps.example")
    {
        return new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            KeyId = "k1",
            Key = _key,
            PersonServer = personServer,
        }.Build();
    }

    [Fact]
    public void WithChallengeHandling_NoArg_BuildsClient()
    {
        var token = BuildAgentToken();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling()
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithChallengeHandling_ExplicitPs_BuildsClient()
    {
        var token = BuildAgentToken(personServer: null);
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example")
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithChallengeHandling_NoArg_NoPsClaim_Throws()
    {
        var token = BuildAgentToken(personServer: null);
        var builder = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling()
            .WithInnerHandler(new StubHandler());

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("ps", ex.Message);
    }

    [Fact]
    public void WithChallengeHandling_WithOptions_BuildsClient()
    {
        var token = BuildAgentToken();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example", opts =>
            {
                opts.PollingTimeout = TimeSpan.FromMinutes(2);
            })
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithChallengeHandling_RequiresJwt()
    {
        var builder = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithChallengeHandling("https://ps.example")
            .WithInnerHandler(new StubHandler());

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void WithTokenRefresh_Interface_BuildsClient()
    {
        var token = BuildAgentToken();
        var refresher = new FakeRefresher();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example")
            .WithTokenRefresh(refresher)
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithTokenRefresh_Delegate_BuildsClient()
    {
        var token = BuildAgentToken();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example")
            .WithTokenRefresh(async (ctx, ct) => ctx.CurrentToken)
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void UseJwt_StringOverload_BuildsClient()
    {
        var token = BuildAgentToken();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public async Task ChallengeHandling_SignsRequests()
    {
        var token = BuildAgentToken();
        var handler = new StubHandler();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example")
            .WithInnerHandler(handler)
            .Build();

        await client.GetAsync("https://resource.example/api");
        Assert.True(handler.LastRequest!.Headers.Contains("Signature"));
        Assert.True(handler.LastRequest.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public async Task ChallengeHandling_AutoAdds_AuthTokenCapability()
    {
        var token = BuildAgentToken();
        var handler = new StubHandler();
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(token)
            .WithChallengeHandling("https://ps.example")
            .WithInnerHandler(handler)
            .Build();

        await client.GetAsync("https://resource.example/api");
        Assert.True(handler.LastRequest!.Headers.Contains("AAuth-Capabilities"));
        var caps = string.Join(",", handler.LastRequest.Headers.GetValues("AAuth-Capabilities"));
        Assert.Contains("auth-token", caps);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class FakeRefresher : ITokenRefresher
    {
        public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
            => Task.FromResult(context.CurrentToken);
    }
}
