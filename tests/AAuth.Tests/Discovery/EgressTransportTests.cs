using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Access;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Discovery;

public class EgressTransportTests
{
    [Theory]
    [InlineData("192.0.78.24")]
    [InlineData("192.0.1.1")]
    [InlineData("192.0.3.1")]
    [InlineData("192.0.0.9")]
    [InlineData("192.0.0.10")]
    [InlineData("::ffff:192.0.78.24")]
    [InlineData("2001:500:2::c")]
    [InlineData("2001:200::1")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("2001:1::1")]
    [InlineData("2001:1::2")]
    [InlineData("2001:1::3")]
    [InlineData("2001:3::1")]
    [InlineData("2001:4:112::1")]
    [InlineData("2001:20::1")]
    [InlineData("2001:30::1")]
    [InlineData("3fff:1000::1")]
    public async Task ProductionAdmitsPublicDnsWithoutOverbroadPrefixes(string address)
    {
        var resolver = new Resolver(IPAddress.Parse(address));
        var policy = new AAuthEgressPolicy(dnsResolver: resolver);
        await policy.ValidateDestinationAsync("https://server.example/document");
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public void OwnedTransportDoesNotExposeMutableInnerChain()
    {
        using var handler = AAuthHttpTransport.CreateHandler();
        Assert.False(handler is DelegatingHandler);
    }

    [Fact]
    public void FederationDoesNotInferContractThroughUntrustedWrapper()
    {
        var services = new ServiceCollection();
        using var http = AAuthHttpTransport.CreateClient();
        services.AddSingleton(new MetadataClient(http));
        services.AddSingleton(new JwksClient(http));
        services.AddAAuthFederation(AAuth.Crypto.AAuthKey.Generate(), "https://person.example", "key");
        services.AddHttpClient(AAuthFederationServiceCollectionExtensions.FederationHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new UntrustedWrapper
            {
                InnerHandler = AAuthHttpTransport.CreateHandler(),
            });
        using var provider = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<AccessServerClient>());
    }

    [Fact]
    public async Task FederationCannotBeRetargetedAfterDefaultContractInference()
    {
        var services = new ServiceCollection();
        var dns = new Resolver(IPAddress.Loopback);
        var policy = new AAuthEgressPolicy(dnsResolver: dns);
        using var http = AAuthHttpTransport.AttachPolicy(new HttpClient(new FederationMetadataHandler()), policy,
            AAuthTransportContract.InProcessOnly);
        services.AddSingleton(new MetadataClient(http));
        services.AddSingleton(new JwksClient(http));
        services.AddAAuthFederation(AAuth.Crypto.AAuthKey.Generate(), "https://person.example", "key");
        using var provider = services.BuildServiceProvider();
        var federation = provider.GetRequiredService<AccessServerClient>();
        var chain = Assert.IsAssignableFrom<DelegatingHandler>(provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(AAuthFederationServiceCollectionExtensions.FederationHttpClientName));
        using var bypass = new UntrustedWrapper { InnerHandler = new HttpClientHandler() };
        var original = Assert.IsAssignableFrom<HttpMessageHandler>(chain.InnerHandler);
        try
        {
            chain.InnerHandler = bypass;
            await Assert.ThrowsAsync<HttpRequestException>(() => federation.FederateAsync("https://access.example", new()
            {
                ResourceToken = "resource", AgentToken = "agent", ExpectedAudience = "https://resource.example",
                ExpectedSubject = "person", ExpectedPersonServer = "https://ps.example", AgentKey = AAuth.Crypto.AAuthKey.Generate(),
                PresentedToken = "presented", PresentedTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                AuthorizationExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            }));
            Assert.Equal(0, bypass.Calls);
            Assert.Equal(1, dns.Calls);
        }
        finally { chain.InnerHandler = original; }
    }

    [Fact]
    public void FederationAcceptsExplicitCustomTransportContract()
    {
        var services = new ServiceCollection();
        using var http = AAuthHttpTransport.CreateClient();
        services.AddSingleton(new MetadataClient(http));
        services.AddSingleton(new JwksClient(http));
        services.AddAAuthFederation(AAuth.Crypto.AAuthKey.Generate(), "https://person.example", "key");
        services.AddHttpClient(AAuthFederationServiceCollectionExtensions.FederationHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new UntrustedWrapper { InnerHandler = new HttpClientHandler() });
        services.Configure<AAuthFederationOptions>(options => options.TransportContract = AAuthTransportContract.InProcessOnly);
        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<AccessServerClient>());
    }

    private sealed class FederationMetadataHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"issuer\":\"https://access.example\",\"auth_token_endpoint\":\"https://access.example/token\"}"),
            });
    }

    private sealed class UntrustedWrapper : DelegatingHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CrossOriginDiscoveryRequiresAdmissionBeforeJwksConnection(bool admitted)
    {
        using var metadataServer = new LocalServer();
        using var keysServer = new LocalServer();
        var policy = new AAuthEgressPolicy([metadataServer.Origin, keysServer.Origin],
            crossOriginJwks: admitted ? [(metadataServer.Origin, keysServer.Origin)] : []);
        using var http = AAuthHttpTransport.CreateClient(policy);
        var metadata = new MetadataClient(http);
        var keys = new JwksClient(http);
        var key = AAuth.Crypto.AAuthKey.Generate();
        var jwk = key.ToPublicJwk();
        jwk["kid"] = "key";
        var metadataBody = new System.Text.Json.Nodes.JsonObject
        {
            ["issuer"] = metadataServer.Origin,
            ["jwks_uri"] = keysServer.Origin + "/jwks",
        }.ToJsonString();
        var servingMetadata = metadataServer.RespondAsync(JsonResponse(metadataBody));
        var info = new AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo
        {
            Scheme = "jwks_uri", Identifier = metadataServer.Origin, Dwk = "aauth-agent.json", Kid = "key",
        };
        var resolver = new AAuth.HttpSig.DefaultSignatureKeyResolver(keys, metadata);
        if (admitted)
        {
            var keysBody = new System.Text.Json.Nodes.JsonObject { ["keys"] = new System.Text.Json.Nodes.JsonArray(jwk) }.ToJsonString();
            var servingKeys = keysServer.RespondAsync(JsonResponse(keysBody));
            var resolved = await resolver.ResolveAsync(info);
            Assert.Equal(key.ComputeJwkThumbprint(), resolved.PublicKey.ComputeJwkThumbprint());
            await servingKeys;
        }
        else
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => resolver.ResolveAsync(info));
            Assert.False(keysServer.Pending);
        }
        await servingMetadata;
    }

    [Fact]
    public void InjectedClientsAndHandlersRequireAnExplicitContract()
    {
        using var http = new HttpClient();
        Assert.Throws<InvalidOperationException>(() => new MetadataClient(http));
        Assert.Throws<InvalidOperationException>(() => new JwksClient(http));
        Assert.Throws<ArgumentException>(() => new AAuthClientBuilder(AAuth.Crypto.AAuthKey.Generate())
            .UseHwk().WithInnerHandler(new HttpClientHandler()).Build());
    }

    [Fact]
    public void ExplicitPolicyCannotBeOverriddenByAnInjectedClient()
    {
        using var http = AAuthHttpTransport.CreateClient(AAuthEgressPolicy.ForDevelopmentLoopback("http://localhost:5100"));
        Assert.Throws<InvalidOperationException>(() => new MetadataClient(http, policy: AAuthEgressPolicy.Production));
        Assert.Throws<InvalidOperationException>(() => new JwksClient(http, policy: AAuthEgressPolicy.Production));
    }

    [Fact]
    public async Task InteractionAdmissionRejectsPrivateDnsBeforeCallbackNavigation()
    {
        var resolver = new Resolver(IPAddress.Parse("169.254.169.254"));
        using var client = AAuthHttpTransport.CreateClient(new(dnsResolver: resolver));
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            AAuthHttpTransport.AdmitInteractionAsync(client, "https://interaction.example/consent"));
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task PendingPollUsesTheBoundedNoRedirectTransport()
    {
        using var server = new LocalServer();
        using var client = AAuthHttpTransport.CreateClient(AAuthEgressPolicy.ForDevelopmentLoopback(server.Origin));
        var serving = server.RespondAsync("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        var poller = new AAuth.Agent.DeferredPoller(client);
        await Assert.ThrowsAsync<HttpRequestException>(() => poller.PollAsync(new Uri(server.Origin + "/pending")));
        await serving;
        Assert.False(server.Pending);
    }

    [Theory]
    [InlineData("https://Issuer.example")]
    [InlineData("https://issuer.example:443")]
    [InlineData("https://issuer.example/")]
    [InlineData("https://issuer.example?")]
    [InlineData("https://issuer.example#")]
    [InlineData("https://user@issuer.example")]
    [InlineData("https://m\u00fcnchen.example")]
    public async Task RawIdentifierRejectedByResolverBeforeDns(string identifier)
    {
        var dns = new Resolver(IPAddress.Parse("8.8.8.8"));
        using var http = AAuthHttpTransport.CreateClient(new(dnsResolver: dns));
        var resolver = new AAuth.HttpSig.DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http));
        await Assert.ThrowsAsync<AAuth.HttpSig.AAuthVerificationException>(() => resolver.ResolveAsync(new()
        {
            Scheme = "jwks_uri", Identifier = identifier, Dwk = "aauth-agent.json", Kid = "key",
        }));
        Assert.Equal(0, dns.Calls);
    }

    private static string JsonResponse(string json) =>
        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(json)}\r\nConnection: close\r\n\r\n{json}";

    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.1.1")]
    [InlineData("192.168.1.1")]
    [InlineData("100.64.1.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    [InlineData("2002:7f00:1::")]
    [InlineData("192.0.0.8")]
    [InlineData("192.0.0.11")]
    [InlineData("192.0.0.170")]
    [InlineData("192.0.2.1")]
    [InlineData("192.88.99.2")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::ffff:192.0.2.1")]
    [InlineData("::ffff:10.1.2.3")]
    [InlineData("::ffff:169.254.1.1")]
    [InlineData("::")]
    [InlineData("64:ff9b::7f00:1")]
    [InlineData("100::1")]
    [InlineData("2001::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:10::1")]
    [InlineData("2001:1ff::1")]
    [InlineData("2001:db8::1")]
    [InlineData("3fff:fff::1")]
    [InlineData("5f00::1")]
    [InlineData("ff02::1")]
    public async Task ProductionRejectsNonPublicDnsAtConnection(string address)
    {
        var resolver = new Resolver(IPAddress.Parse(address));
        using var client = AAuthHttpTransport.CreateClient(new(dnsResolver: resolver));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("https://server.example/document"));
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task MixedDnsResultsRejectBeforeConnecting()
    {
        var resolver = new Resolver(IPAddress.Parse("8.8.8.8"), IPAddress.Loopback);
        using var client = AAuthHttpTransport.CreateClient(new(dnsResolver: resolver));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("https://server.example/document"));
        Assert.Equal(1, resolver.Calls);
    }

    [Theory]
    [InlineData("http://localhost:4321/document")]
    [InlineData("https://127.0.0.1/document")]
    [InlineData("https://10.0.0.1/document")]
    public async Task ProductionRejectsLiteralPrivateAndHttp(string url)
    {
        using var client = AAuthHttpTransport.CreateClient();
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(url));
    }

    [Fact]
    public async Task ConfiguredLoopbackPinsOneResolutionAndConnectsToThatAddress()
    {
        using var server = new LocalServer();
        var resolver = new Resolver(IPAddress.Loopback) { Rebound = IPAddress.Parse("10.0.0.1") };
        var policy = new AAuthEgressPolicy([server.Origin], dnsResolver: resolver);
        using var client = AAuthHttpTransport.CreateClient(policy);
        var serving = server.RespondAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        Assert.Equal("ok", await client.GetStringAsync(server.Origin + "/document"));
        await serving;
        Assert.Equal(1, resolver.Calls);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Origin + "/document"));
        Assert.Equal(2, resolver.Calls);
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest")]
    [InlineData("https://other.example/jwks")]
    [InlineData("/same-host")]
    public async Task RedirectsAreNeverFollowed(string destination)
    {
        using var server = new LocalServer();
        using var client = AAuthHttpTransport.CreateClient(AAuthEgressPolicy.ForDevelopmentLoopback(server.Origin));
        var serving = server.RespondAsync($"HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Origin + "/document"));
        await serving;
        Assert.False(server.Pending);
    }

    [Theory]
    [InlineData("Content-Length: 5\r\n", "12345")]
    [InlineData("Transfer-Encoding: chunked\r\n", "5\r\n12345\r\n0\r\n\r\n")]
    public async Task ResponseBodyIsBoundedWithAndWithoutLength(string header, string body)
    {
        using var server = new LocalServer();
        using var client = AAuthHttpTransport.CreateClient(new([server.Origin], maxResponseBytes: 4));
        var serving = server.RespondAsync($"HTTP/1.1 200 OK\r\n{header}Connection: close\r\n\r\n{body}");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Origin + "/document"));
        await serving;
    }

    [Fact]
    public async Task DeadlineIncludesSlowBody()
    {
        using var server = new LocalServer();
        using var client = AAuthHttpTransport.CreateClient(new([server.Origin], requestTimeout: TimeSpan.FromSeconds(2)));
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serving = server.RespondAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", release.Task);
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync(server.Origin + "/document"));
        }
        finally
        {
            release.SetResult();
            await serving;
        }
    }

    [Fact]
    public void CrossOriginRequiresExactPair()
    {
        Assert.Throws<HttpRequestException>(() => AAuthEgressPolicy.Production.ValidateJwksUrl("https://cdn.example/jwks", "https://issuer.example"));
        var policy = new AAuthEgressPolicy(crossOriginJwks: [("https://issuer.example", "https://cdn.example")]);
        Assert.Equal("https://cdn.example/jwks", policy.ValidateJwksUrl("https://cdn.example/jwks", "https://issuer.example").OriginalString);
        Assert.Throws<HttpRequestException>(() => policy.ValidateJwksUrl("https://cdn.example/jwks", "https://other.example"));
    }

    [Theory]
    [InlineData("https://Issuer.example")]
    [InlineData("HTTPS://issuer.example")]
    [InlineData("https://issuer.example/")]
    [InlineData("https://issuer.example:443")]
    [InlineData("https://issuer.example:8443")]
    [InlineData("https://issuer.example/path")]
    [InlineData("https://issuer.example?")]
    [InlineData("https://issuer.example#")]
    [InlineData("https://user@issuer.example")]
    [InlineData(" https://issuer.example")]
    [InlineData("https://%69ssuer.example")]
    [InlineData("https://issuer.example.")]
    public void IdentifierIsCheckedBeforeNormalization(string identifier) =>
        Assert.False(AAuthEgressPolicy.Production.IsValidIdentifier(identifier));

    private sealed class Resolver(params IPAddress[] addresses) : IAAuthDnsResolver
    {
        public int Calls { get; private set; }
        public IPAddress? Rebound { get; init; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(Calls > 1 && Rebound is not null ? [Rebound] : addresses);
        }
    }

    private sealed class LocalServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        public string Origin { get; }
        public bool Pending => _listener.Pending();
        public LocalServer()
        {
            _listener.Start();
            Origin = $"http://localhost:{((IPEndPoint)_listener.LocalEndpoint).Port}";
        }
        public async Task RespondAsync(string response, Task? holdOpen = null)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var connection = await _listener.AcceptTcpClientAsync(deadline.Token);
            await using var stream = connection.GetStream();
            using var reader = new StreamReader(stream, leaveOpen: true);
            while (!string.IsNullOrEmpty(await reader.ReadLineAsync(deadline.Token))) { }
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), deadline.Token);
            if (holdOpen is not null) await holdOpen.WaitAsync(deadline.Token);
        }
        public void Dispose() => _listener.Stop();
    }
}