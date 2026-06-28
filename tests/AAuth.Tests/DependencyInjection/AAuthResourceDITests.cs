using System;
using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
            opts.Name = "Test Resource";
        });

        var provider = services.BuildServiceProvider();
        var metadata = provider.GetRequiredService<AAuthResourceMetadataOptions>();
        Assert.Equal("https://resource.example", metadata.Issuer);
        Assert.Equal("Test Resource", metadata.Name);
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

    [Fact]
    public void AddAAuthResource_RegistersDiscoveryClients()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
        });

        var provider = services.BuildServiceProvider();
        // The SDK owns the discovery clients (no consumer HttpClient wiring).
        Assert.NotNull(provider.GetRequiredService<MetadataClient>());
        Assert.NotNull(provider.GetRequiredService<JwksClient>());
    }

    [Fact]
    public void AddAAuthResource_PublishesNewMetadataFields()
    {
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
            opts.SignatureWindow = 90;
            opts.AccessMode = AAuthConstants.AccessModes.AuthToken;
            opts.AuthorizationEndpoint = "https://resource.example/authorize";
        });

        var provider = services.BuildServiceProvider();
        var metadata = provider.GetRequiredService<AAuthResourceMetadataOptions>();
        Assert.Equal(90, metadata.SignatureWindow);
        Assert.Equal(AAuthConstants.AccessModes.AuthToken, metadata.AccessMode);
        Assert.Equal("https://resource.example/authorize", metadata.AuthorizationEndpoint);
    }

    [Fact]
    public void AddAAuthResource_DiscoveryClientsRemainOverridable()
    {
        // The integration harness overrides discovery by RemoveAll + re-add; the
        // SDK registers via TryAdd so an explicit later registration wins (G4).
        var services = new ServiceCollection();
        services.AddAAuthResource(opts =>
        {
            opts.Issuer = "https://resource.example";
            opts.SigningKeys["k1"] = _key;
        });

        var custom = new JwksClient(new System.Net.Http.HttpClient());
        services.RemoveAll<JwksClient>();
        services.AddSingleton(custom);

        var provider = services.BuildServiceProvider();
        Assert.Same(custom, provider.GetRequiredService<JwksClient>());
    }
}
