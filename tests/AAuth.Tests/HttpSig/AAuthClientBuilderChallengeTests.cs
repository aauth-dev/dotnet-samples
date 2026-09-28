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

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task RefreshPipelinePreservesCurrentToken(bool challenge, bool factory, bool nearExpiry)
    {
        var issued = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        string CreateToken(TimeSpan lifetime) => new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:refresh@ap.example", KeyId = "agent-key",
            Key = _key, IssuedAt = issued, Lifetime = lifetime, PersonServer = "https://ps.example",
            AdditionalClaims = new Dictionary<string, System.Text.Json.Nodes.JsonNode?> { ["account"] = System.Text.Json.Nodes.JsonValue.Create("account-a") },
        }.Build();
        var initial = CreateToken(nearExpiry ? TimeSpan.FromSeconds(30) : TimeSpan.FromMinutes(10));
        var replacement = CreateToken(TimeSpan.FromHours(1));
        var current = initial;
        var factoryCalls = 0;
        var refreshCalls = 0;
        var network = new RefreshRecordingHandler();
        var builder = new AAuthClientBuilder(_key);
        if (factory) builder.UseJwt(() => { factoryCalls++; return current; });
        else builder.UseJwt(initial);
        builder.WithTokenRefresh((context, cancellation) =>
        {
            refreshCalls++;
            Assert.Equal(current, context.CurrentToken);
            Assert.Equal("https://ap.example", context.Issuer);
            Assert.Equal("aauth:refresh@ap.example", context.AgentId);
            Assert.Equal("account-a", context.Account);
            Assert.Equal(_key.ComputeJwkThumbprint(), context.SigningKeyThumbprint);
            Assert.False(cancellation.IsCancellationRequested);
            return Task.FromResult(replacement);
        });
        if (challenge) builder.WithChallengeHandling("https://ps.example");
        Assert.Equal(0, factoryCalls);
        Assert.Equal(0, refreshCalls);
        using var client = builder.WithInnerHandler(network, AAuth.Discovery.AAuthTransportContract.InProcessOnly).Build();
        await client.GetAsync("https://resource.example/api");
        Assert.Equal(nearExpiry ? 1 : 0, refreshCalls);
        Assert.Equal(nearExpiry ? replacement : initial, network.Tokens[^1]);
        Assert.Equal(issued.Add(nearExpiry ? TimeSpan.FromHours(1) : TimeSpan.FromMinutes(10)),
            new TokenVerifier().VerifySelfIssuedAgentToken(network.Tokens[^1], _key).ExpiresAt);
        await client.GetAsync("https://resource.example/api");
        Assert.Equal(nearExpiry ? 1 : 0, refreshCalls);
        Assert.Equal(nearExpiry ? replacement : initial, network.Tokens[^1]);
        if (factory)
        {
            current = CreateToken(TimeSpan.FromMinutes(20));
            await client.GetAsync("https://resource.example/api");
            Assert.Equal(current, network.Tokens[^1]);
        }
        var beforeCancellation = factoryCalls;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync("https://resource.example/api", new CancellationToken(true)));
        Assert.Equal(beforeCancellation, factoryCalls);
        Assert.Equal(factory ? 3 : 2, network.Tokens.Count);
        client.Dispose();
        Assert.True(network.Disposed);
    }

    private sealed class RefreshRecordingHandler : HttpMessageHandler
    {
        public List<string> Tokens { get; } = [];
        public bool Disposed { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Tokens.Add(SignatureKeyParser.ParseAny(string.Join(",", request.Headers.GetValues("Signature-Key"))).Jwt!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) Disposed = true;
            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task ChallengeFromAnotherResourceIsRejectedBeforeExchange()
    {
        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = "https://other-resource.example",
            Audience = "https://ps.example",
            PersonServer = "https://ps.example",
            Subject = "person",
            PresentedJti = "person-jti",
            AgentJkt = _key.ComputeJwkThumbprint(),
            Key = _key,
            KeyId = "resource-key",
        }.Build();
        using var client = new AAuthClientBuilder(_key).UseJwt(BuildAgentToken())
            .WithChallengeHandling("https://ps.example")
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(new ChallengeResponseHandler(resourceToken), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();

        var error = await Assert.ThrowsAsync<TokenVerificationException>(
            () => client.GetAsync("https://resource.example/api"));

        Assert.Contains("issuer", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ChallengeResponseHandler(string resourceToken) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name,
                $"requirement=auth-token; resource-token=\"{resourceToken}\"");
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task ChallengeFactoryBuildUsesCurrentClaimsInsteadOfSelectionSnapshot()
    {
        var current = BuildAgentToken(personServer: null);
        var calls = 0;
        var handler = new StubHandler();
        var builder = new AAuthClientBuilder(_key).UseJwt(() => { calls++; return current; })
            .WithChallengeHandling()
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(handler, AAuth.Discovery.AAuthTransportContract.InProcessOnly);
        Assert.Equal(0, calls);
        current = BuildAgentToken("https://current-ps.example");
        using var client = builder.Build();
        await client.GetAsync("https://resource.example/api");
        Assert.Equal(current, SignatureKeyParser.ParseAny(string.Join(",", handler.LastRequest!.Headers.GetValues("Signature-Key"))).Jwt);
        Assert.Equal(2, calls);
    }

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
