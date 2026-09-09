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

    [Fact]
    public async Task ChallengeFactoryRemainsLiveAndCancelledRequestsDoNotReadIt()
    {
        var first = BuildAgentToken();
        var second = new AgentTokenBuilder { Issuer = "https://other.example", Subject = "aauth:other@example.com",
            Key = _key, KeyId = "k2", ConfirmationKey = _key }.Build();
        var current = first;
        var calls = 0;
        var handler = new StubHandler();
        using var client = new AAuthClientBuilder(_key).UseJwt(() => { calls++; return current; })
            .WithChallengeHandling("https://ps.example")
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(handler, AAuth.Discovery.AAuthTransportContract.InProcessOnly).Build();
        await client.GetAsync("https://resource.example/api");
        Assert.Equal(first, SignatureKeyParser.ParseAny(string.Join(",", handler.LastRequest!.Headers.GetValues("Signature-Key"))).Jwt);
        current = second;
        await client.GetAsync("https://resource.example/api");
        Assert.Equal(second, SignatureKeyParser.ParseAny(string.Join(",", handler.LastRequest!.Headers.GetValues("Signature-Key"))).Jwt);
        var beforeCancel = calls;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync("https://resource.example/api", new CancellationToken(true)));
        Assert.Equal(beforeCancel, calls);
    }

    private string BuildAgentToken(string? personServer = "https://ps.example")
    {
        return new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly);

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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithChallengeHandling_RequiresJwt()
    {
        var builder = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithChallengeHandling("https://ps.example")
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly);

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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new StubHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(handler, AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(handler, AAuth.Discovery.AAuthTransportContract.InProcessOnly)
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
