using System.Net;
using System.Net.Http;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public sealed class ClientCompositionTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    private ValueTask<string> TokenAsync(int seconds = 3600) => new AgentTokenBuilder
    {
        Issuer = "https://ap.example", Subject = "aauth:agent@ap.example",
        Key = _key, KeyId = "agent-key", Lifetime = TimeSpan.FromSeconds(seconds),
    }.BuildAsync();

    private EnrollResult Enrollment(string token, bool hasJwks = true) => new()
    {
        Key = _key, AgentToken = token, LocalKeyHandle = "durable-key",
        JwksUri = hasJwks ? "https://ap.example/keys" : null,
        AgentTokenKid = hasJwks ? "published-key" : null,
    };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task From_UsesEnrollmentJwtRegardlessOfJwks(bool hasJwks)
    {
        var token = await TokenAsync();
        var transport = new CaptureTransport();
        using var client = AAuthClientBuilder.From(Enrollment(token, hasJwks))
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.GetAsync("https://resource.example/messages");
        Assert.Equal($"sig=jwt;jwt=\"{token}\"", transport.Carriers.Single());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task From_RefreshUpdatesJwtCarrier(bool challenge)
    {
        var token = await TokenAsync();
        var refresher = new TrackingRefresher(token);
        var transport = new CaptureTransport();
        var builder = AAuthClientBuilder.From(Enrollment(await TokenAsync(10)))
            .WithTokenRefresh(refresher)
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly);
        if (challenge) builder.WithChallengeHandling("https://ps.example");
        using var client = builder.Build();
        using var response = await client.GetAsync("https://resource.example/messages");
        Assert.Equal(1, refresher.Calls);
        Assert.Equal($"sig=jwt;jwt=\"{token}\"", transport.Carriers.Single());
    }

    [Theory]
    [InlineData("hwk")]
    [InlineData("jwt")]
    [InlineData("jwks_uri")]
    [InlineData("jwks")]
    [InlineData("jkt-jwt")]
    [InlineData("self-jwt")]
    [InlineData("provider")]
    public async Task ExplicitSchemeAfterRefreshSuppressesRefresh(string scheme)
    {
        var token = await TokenAsync();
        var refresher = new TrackingRefresher(token);
        var transport = new CaptureTransport();
        var builder = AAuthClientBuilder.From(Enrollment(token)).WithTokenRefresh(refresher);
        switch (scheme)
        {
            case "hwk": builder.UseHwk(); break;
            case "jwt": builder.UseJwt(token); break;
            case "jwks_uri": builder.UseJwksUri("https://agent.example", "aauth-agent.json", "key"); break;
            case "jwks": builder.UseJwks("https://agent.example/keys", "key"); break;
            case "jkt-jwt":
                var namingJwt = await NamingJwtBuilder.BuildAsync(_key, _key);
                builder.UseJktJwt(() => namingJwt);
                break;
            case "self-jwt": builder.UseSelfJwt(() => token); break;
            case "provider": builder.UseProvider(new HwkSignatureKeyProvider(_key)); break;
        }
        using var client = builder.WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.GetAsync("https://resource.example/messages");
        Assert.StartsWith($"sig={(scheme == "provider" ? "hwk" : scheme)};", transport.Carriers.Single());
        Assert.Equal(0, refresher.Calls);
    }

    [Fact]
    public async Task RefreshAfterExplicitSchemeSelectsJwt()
    {
        var refresher = new TrackingRefresher(await TokenAsync());
        var transport = new CaptureTransport();
        using var client = new AAuthClientBuilder(_key).UseHwk().WithTokenRefresh(refresher)
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.GetAsync("https://resource.example/messages");
        Assert.StartsWith("sig=jwt;", transport.Carriers.Single());
        Assert.Equal(1, refresher.Calls);
    }

    [Fact]
    public async Task SelfIssuing_ResourceManagedCompositionUsesAgentJwtAndReplaysOpaqueCredential()
    {
        var transport = new CaptureTransport();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As("https://ap.example", "aauth:agent@ap.example")
            .WithResourceManagedAccess().WithInteractionHandling()
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        using var first = await client.GetAsync("https://resource.example/messages");
        using var second = await client.GetAsync("https://resource.example/messages");
        Assert.Equal(2, transport.Carriers.Count);
        Assert.All(transport.Carriers, carrier => Assert.StartsWith("sig=jwt;", carrier));
        Assert.Equal(new string?[] { null, "AAuth opaque-token" }, transport.Authorizations);
        Assert.All(transport.Capabilities, capabilities => Assert.Contains("interaction", capabilities));
        Assert.Contains("\"authorization\"", transport.SignatureInputs.Last());
        Assert.All(transport.Targets, target => Assert.Equal("resource.example", target.Host));
    }

    [Fact]
    public async Task DefaultPolicyRejectsLoopbackBeforeTransport()
    {
        var transport = new CaptureTransport();
        using var client = AAuthClientBuilder.From(Enrollment(await TokenAsync()))
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        await Assert.ThrowsAnyAsync<Exception>(() => client.GetAsync("http://localhost:9999/messages"));
        Assert.Empty(transport.Targets);
    }

    [Fact]
    public async Task EnrolledTransitionDoesNotSelectTopologyOrAcquireTokenBeforeSend()
    {
        var transport = new CaptureTransport();
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom("https://ap.example/refresh", "local-key")
            .WithKeyStore(new InMemoryKeyStore()).ToBuilder()
            .UseJwt(await TokenAsync()).WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).Build();
        Assert.Empty(transport.Targets);
        using var response = await client.GetAsync("https://resource.example/messages");
        Assert.Equal("", transport.Capabilities.Single());
        Assert.Null(transport.Authorizations.Single());
    }

    [Fact]
    public async Task PipelineOwnsFactoryRefresherButNotInjectedRefresher()
    {
        var created = new List<TrackingRefresher>();
        var token = await TokenAsync();
        var builder = new AAuthClientBuilder(_key).WithOwnedTokenRefresh(_ =>
        {
            var refresher = new TrackingRefresher(token);
            created.Add(refresher);
            return refresher;
        });
        Assert.Empty(created);
        var first = builder.BuildHandler();
        var second = builder.BuildHandler();
        first.Dispose();
        first.Dispose();
        Assert.Equal(1, created[0].Disposals);
        Assert.Equal(0, created[1].Disposals);
        second.Dispose();
        Assert.Equal(1, created[1].Disposals);
        var borrowed = new TrackingRefresher(await TokenAsync());
        new AAuthClientBuilder(_key).WithTokenRefresh(borrowed).Build().Dispose();
        Assert.Equal(0, borrowed.Disposals);
    }

    [Fact]
    public async Task FailedInteractionConfigurationDisposesPartialTransport()
    {
        var transport = new CaptureTransport();
        var refresher = new TrackingRefresher(await TokenAsync());
        Assert.Throws<InvalidOperationException>(() => new AAuthClientBuilder(_key)
            .WithOwnedTokenRefresh(_ => refresher)
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly)
            .WithInteractionHandling(_ => throw new InvalidOperationException("configuration failure"))
            .Build());
        Assert.Equal(1, transport.Disposals);
        Assert.Equal(1, refresher.Disposals);
    }

    [Fact]
    public async Task DiscoveryDisposalDoesNotDisposeInjectedClient()
    {
        var transport = new CaptureTransport();
        using var http = new InProcessHttpClient(transport);
        new MetadataClient(http).Dispose();
        new JwksClient(http).Dispose();
        Assert.Equal(0, transport.Disposals);
        using var response = await http.GetAsync("https://ap.example/alive");
    }

    [Fact]
    public async Task FailedBuildDisposesOwnedRefresher()
    {
        var refresher = new TrackingRefresher(await TokenAsync());
        Assert.Throws<InvalidOperationException>(() => new AAuthClientBuilder(_key)
            .WithOwnedTokenRefresh(_ => refresher).WithChallengeHandling().Build());
        Assert.Equal(1, refresher.Disposals);
    }

    [Fact]
    public void GovernanceRejectsGenericCarrierBeforeCreatingTransport()
    {
        var transport = new CaptureTransport();
        Assert.Throws<InvalidOperationException>(() => new AAuthClientBuilder(_key)
            .UseHwk().WithPersonServer("https://ps.example")
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly).BuildGovernance());
        Assert.Empty(transport.Targets);
    }

    [Fact]
    public void GovernanceBuilderSupportsSelfIssuingAndOwnsTransport()
    {
        var transport = new CaptureTransport();
        var governance = AAuthClientBuilder.SelfIssuing(_key)
            .As("https://ap.example", "aauth:agent@ap.example")
            .WithPersonServer("https://ps.example")
            .WithInnerHandler(transport, AAuthTransportContract.InProcessOnly)
            .BuildGovernance();
        Assert.Empty(transport.Targets);
        governance.Dispose();
        governance.Dispose();
        Assert.Equal(1, transport.Disposals);
    }

    [Fact]
    public async Task FactoryRefresherIsDisposableAndBorrowsInjectedHttpClient()
    {
        var transport = new CaptureTransport();
        using var http = new InProcessHttpClient(transport);
        using (var refresher = AgentProviderTokenRefresher.Create("https://ap.example/refresh", "key")
            .WithHttpClient(http).WithKeyStore(new InMemoryKeyStore()).Build())
        {
            refresher.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => refresher.RefreshAsync(null!, default));
        }
        Assert.Equal(0, transport.Disposals);
        using var response = await http.GetAsync("https://ap.example/alive");
    }

    private sealed class TrackingRefresher(string token) : ITokenRefresher, IDisposable
    {
        public int Calls { get; private set; }
        public int Disposals { get; private set; }
        public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(token);
        }
        public void Dispose() => Disposals++;
    }

    private sealed class CaptureTransport : HttpMessageHandler
    {
        public List<string> Carriers { get; } = [];
        public List<string?> Authorizations { get; } = [];
        public List<string> SignatureInputs { get; } = [];
        public List<string> Capabilities { get; } = [];
        public List<Uri> Targets { get; } = [];
        public int Disposals { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Targets.Add(request.RequestUri!);
            Carriers.Add(request.Headers.TryGetValues("Signature-Key", out var carriers) ? string.Join("", carriers) : "");
            SignatureInputs.Add(request.Headers.TryGetValues("Signature-Input", out var inputs) ? string.Join("", inputs) : "");
            Capabilities.Add(request.Headers.TryGetValues("AAuth-Capabilities", out var capabilities) ? string.Join("", capabilities) : "");
            Authorizations.Add(request.Headers.Authorization?.ToString());
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.Add("AAuth-Access", "opaque-token");
            return Task.FromResult(response);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) Disposals++;
            base.Dispose(disposing);
        }
    }
}