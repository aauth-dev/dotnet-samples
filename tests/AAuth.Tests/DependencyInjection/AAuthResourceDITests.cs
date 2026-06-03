using System;
using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

public class AAuthResourceDITests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    [Fact]
    public void AddAAuthResource_RegistersVerifier()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
        });

        var provider = services.BuildServiceProvider();
        var verifier = provider.GetRequiredService<AAuthVerifier>();
        Assert.NotNull(verifier);
        Assert.Equal(TimeSpan.FromSeconds(60), verifier.MaxAge);
    }

    [Fact]
    public void AddAAuthResource_RegistersKeyResolver()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
        });

        var provider = services.BuildServiceProvider();
        var resolver = provider.GetRequiredService<ISignatureKeyResolver>();
        Assert.IsType<DefaultSignatureKeyResolver>(resolver);
    }

    [Fact]
    public void AddAAuthResource_RegistersJtiStore_WhenReplayDetectionEnabled()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.EnableReplayDetection = true;
        });

        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IJtiStore>();
        Assert.IsType<InMemoryJtiStore>(store);
    }

    [Fact]
    public void AddAAuthResource_NoJtiStore_WhenReplayDetectionDisabled()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.EnableReplayDetection = false;
        });

        var provider = services.BuildServiceProvider();
        var store = provider.GetService<IJtiStore>();
        Assert.Null(store);
    }

    [Fact]
    public void AddAAuthResource_RegistersMetadataOptions()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.ClientName = "Test Resource";
        });

        var provider = services.BuildServiceProvider();
        var metadata = provider.GetRequiredService<AAuthResourceMetadataOptions>();
        Assert.Equal("https://resource.example", metadata.Issuer);
        Assert.Equal("Test Resource", metadata.ClientName);
    }

    [Fact]
    public void AddAAuthResource_CustomResolver()
    {
        var custom = new DefaultSignatureKeyResolver();
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.KeyResolver = custom;
        });

        var provider = services.BuildServiceProvider();
        var resolver = provider.GetRequiredService<ISignatureKeyResolver>();
        Assert.Same(custom, resolver);
    }

    [Fact]
    public void AddAAuthResource_WithoutIssuer_Throws()
    {
        var services = new ServiceCollection();
        Assert.Throws<InvalidOperationException>(() =>
            services.AddAAuthResource(opts =>
            {
                opts.SigningKeys["k1"] = _key;
            }));
    }

    [Fact]
    public void AddAAuthResource_CustomMaxAge()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.MaxSignatureAge = TimeSpan.FromSeconds(30);
        });

        var provider = services.BuildServiceProvider();
        var verifier = provider.GetRequiredService<AAuthVerifier>();
        Assert.Equal(TimeSpan.FromSeconds(30), verifier.MaxAge);
    }
}
