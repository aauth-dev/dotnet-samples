using AAuth.Crypto;
using AAuth.HttpSig;
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
