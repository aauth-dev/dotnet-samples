using System;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Tests;

/// <summary>R0 precedence: explicit, then keyed by instance name, then unkeyed, then the default.</summary>
public class SeamResolverTests
{
    private sealed record Seam(string Source);

    private static IServiceProvider Services(bool keyed, bool unkeyed)
    {
        var services = new ServiceCollection();
        if (keyed) services.AddKeyedSingleton("tenant-a", new Seam("keyed"));
        if (unkeyed) services.AddSingleton(new Seam("unkeyed"));
        return services.BuildServiceProvider();
    }

    [Fact(DisplayName = "explicit beats keyed")]
    public void Explicit_BeatsKeyed()
        => Assert.Equal("explicit", AAuthSeams.Resolve(Services(true, true), "tenant-a", new Seam("explicit"), () => new Seam("default")).Source);

    [Fact(DisplayName = "keyed beats unkeyed")]
    public void Keyed_BeatsUnkeyed()
        => Assert.Equal("keyed", AAuthSeams.Resolve<Seam>(Services(true, true), "tenant-a", null, () => new Seam("default")).Source);

    [Fact(DisplayName = "keyed falls back to unkeyed for another instance name")]
    public void OtherName_FallsBackToUnkeyed()
        => Assert.Equal("unkeyed", AAuthSeams.Resolve<Seam>(Services(true, true), "tenant-b", null, () => new Seam("default")).Source);

    [Fact(DisplayName = "unkeyed beats default")]
    public void Unkeyed_BeatsDefault()
        => Assert.Equal("unkeyed", AAuthSeams.Resolve<Seam>(Services(false, true), null, null, () => new Seam("default")).Source);

    [Fact(DisplayName = "default when nothing is registered")]
    public void Default_WhenNothingRegistered()
        => Assert.Equal("default", AAuthSeams.Resolve<Seam>(Services(false, false), "tenant-a", null, () => new Seam("default")).Source);
}
