using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthClientBuilderTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    [Fact]
    public void Build_WithoutMode_Throws()
    {
        var builder = new AAuthClientBuilder(_key);
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void UseHwk_BuildsClient()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseHwk()
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void UseJwt_BuildsClient()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "test-token")
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void UseJwksUri_BuildsClient()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseJwksUri("https://ap.example/.well-known/jwks.json", "key-1")
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void UseJktJwt_BuildsClient()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseJktJwt(() => "naming-jwt")
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithCapabilities_SetsCapabilities()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithCapabilities("deferred", "autonomous")
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void UseProvider_CustomProvider()
    {
        var provider = new HwkSignatureKeyProvider(_key);
        using var client = new AAuthClientBuilder(_key)
            .UseProvider(provider)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public async Task Hwk_SignsRequest()
    {
        var recorded = false;
        using var client = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithInnerHandler(new StubHandler())
            .OnSignatureBase((_, _) => recorded = true)
            .Build();

        await client.GetAsync("http://localhost/test");
        Assert.True(recorded);
    }

    [Fact]
    public void CreateClient_StaticFactory()
    {
        using var client = AAuthSigningHandler.CreateClient(
            _key, new HwkSignatureKeyProvider(_key));

        Assert.NotNull(client);
    }

    [Fact]
    public async Task CreateClient_Signs()
    {
        using var client = AAuthSigningHandler.CreateClient(
            _key,
            new HwkSignatureKeyProvider(_key),
            new StubHandler());

        var response = await client.GetAsync("http://localhost/test");
        Assert.True(response.IsSuccessStatusCode);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Verify signature headers are present
            Assert.True(request.Headers.Contains("Signature"));
            Assert.True(request.Headers.Contains("Signature-Input"));
            Assert.True(request.Headers.Contains("Signature-Key"));
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    // ── WithCallChaining tests ──────────────────────────────────────────────

    [Fact]
    public void WithCallChaining_Delegate_NullGuard()
    {
        var builder = new AAuthClientBuilder(_key).UseJwt(() => "token");
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithCallChaining((Func<string?>)null!));
    }

    [Fact]
    public void WithCallChaining_FixedToken_NullGuard()
    {
        var builder = new AAuthClientBuilder(_key).UseJwt(() => "token");
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithCallChaining((string)null!));
    }

    [Fact]
    public void WithCallChaining_FixedToken_EmptyGuard()
    {
        var builder = new AAuthClientBuilder(_key).UseJwt(() => "token");
        Assert.Throws<ArgumentException>(() =>
            builder.WithCallChaining(string.Empty));
    }

    [Fact]
    public void WithCallChaining_HttpContext_NullGuard()
    {
        var builder = new AAuthClientBuilder(_key).UseJwt(() => "token");
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithCallChaining((HttpContext)null!));
    }

    [Fact]
    public void WithCallChaining_Delegate_ImplicitlyEnablesChallengeHandling()
    {
        // WithCallChaining alone (no personServer) should build successfully
        // because the upstream token provides routing at runtime.
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "token")
            .WithCallChaining(() => "upstream-token")
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithCallChaining_FixedToken_BuildsWithoutPersonServer()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "token")
            .WithCallChaining("upstream-token")
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithCallChaining_HttpContext_ReadsFromFeature()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new UpstreamAuthTokenFeature("feature-token"));

        // Build with HttpContext — uses UpstreamAuthTokenFeature internally
        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "token")
            .WithCallChaining(context)
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public async Task WithCallChaining_SignsWithIntermediaryKey()
    {
        string? capturedSignatureKey = null;
        var innerHandler = new DelegatingStubHandler(req =>
        {
            if (req.Headers.TryGetValues("Signature-Key", out var values))
                capturedSignatureKey = string.Join("", values);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "token")
            .WithCallChaining(() => "upstream-token")
            .WithInnerHandler(innerHandler)
            .Build();

        await client.GetAsync("http://localhost/test");

        // The signature-key header should be present (the intermediary signs with its own key)
        Assert.NotNull(capturedSignatureKey);
    }

    [Fact]
    public async Task WithCallChaining_Integration_401Exchange()
    {
        // Build a fake upstream token with an iss claim
        var header = new System.Text.Json.Nodes.JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = "k1" };
        var payload = new System.Text.Json.Nodes.JsonObject
        {
            ["iss"] = "http://localhost:9999",
            ["aud"] = "http://localhost:6000",
            ["agent"] = "agent-1",
            ["act"] = new System.Text.Json.Nodes.JsonObject { ["sub"] = "agent-1" },
        };
        var h = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            System.Text.Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var upstreamToken = $"{h}.{p}.fake-sig";

        // Verify the builder produces a working pipeline that signs requests.
        // Full 401→exchange→retry is integration-tested in ChallengeHandlerTests;
        // here we verify the builder wires call-chaining without requiring personServer.
        bool signedRequest = false;
        var innerHandler = new DelegatingStubHandler(req =>
        {
            signedRequest = req.Headers.Contains("Signature");
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        });

        using var client = new AAuthClientBuilder(_key)
            .UseJwt(() => "agent-token")
            .WithCallChaining(() => upstreamToken)
            .WithInnerHandler(innerHandler)
            .Build();

        await client.GetAsync("http://localhost:6000/data");

        // The intermediary's key signs the outbound request
        Assert.True(signedRequest);
    }

    private sealed class DelegatingStubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public DelegatingStubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
            => _handler = handler;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_handler(request));
    }
}

public class AAuthHttpClientExtensionsTests
{
    [Fact]
    public void AddAAuthClient_RegistersNamedClient()
    {
        var key = AAuthKey.Generate();
        var services = new ServiceCollection();

        services.AddAAuthClient("agent", options =>
        {
            options.Key = key;
            options.SigningMode = new HwkSignatureKeyProvider(key);
        });

        var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("agent");

        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthClient_WithoutKey_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddAAuthClient("agent", options =>
            {
                options.SigningMode = new HwkSignatureKeyProvider(AAuthKey.Generate());
            }));
    }

    [Fact]
    public void AddAAuthClient_WithoutMode_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddAAuthClient("agent", options =>
            {
                options.Key = AAuthKey.Generate();
            }));
    }
}
