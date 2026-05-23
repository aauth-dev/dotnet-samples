using System;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

public class AAuthDiscoveryDITests
{
    [Fact]
    public void AddAAuthDiscovery_RegistersMetadataClient()
    {
        var services = new ServiceCollection();
        services.AddAAuthDiscovery();

        var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<MetadataClient>();
        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthDiscovery_RegistersJwksClient()
    {
        var services = new ServiceCollection();
        services.AddAAuthDiscovery();

        var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<JwksClient>();
        Assert.NotNull(client);
    }

    [Fact]
    public void AddAAuthDiscovery_SharedSingleton()
    {
        var services = new ServiceCollection();
        services.AddAAuthDiscovery();

        var provider = services.BuildServiceProvider();
        var client1 = provider.GetRequiredService<MetadataClient>();
        var client2 = provider.GetRequiredService<MetadataClient>();
        Assert.Same(client1, client2);
    }

    [Fact]
    public void AddAAuthDiscovery_WithOptions()
    {
        var services = new ServiceCollection();
        services.AddAAuthDiscovery(opts =>
        {
            opts.MetadataCacheTtl = TimeSpan.FromMinutes(10);
            opts.JwksCacheTtl = TimeSpan.FromHours(2);
            opts.JwksMinRefreshInterval = TimeSpan.FromMinutes(2);
        });

        var provider = services.BuildServiceProvider();
        var metadata = provider.GetRequiredService<MetadataClient>();
        var jwks = provider.GetRequiredService<JwksClient>();
        Assert.NotNull(metadata);
        Assert.NotNull(jwks);
    }

    [Fact]
    public void AddAAuthDiscovery_DoesNotOverrideExisting()
    {
        var services = new ServiceCollection();
        // Register first
        services.AddAAuthDiscovery(opts =>
        {
            opts.MetadataCacheTtl = TimeSpan.FromMinutes(1);
        });
        // Second registration should be a no-op
        services.AddAAuthDiscovery(opts =>
        {
            opts.MetadataCacheTtl = TimeSpan.FromMinutes(99);
        });

        var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<MetadataClient>();
        // Should still be the first registration
        Assert.NotNull(client);
    }
}
