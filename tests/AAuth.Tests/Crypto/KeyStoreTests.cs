using System;
using System.IO;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Tests;

public class KeyStoreTests : IDisposable
{
    private readonly string _tempDir;

    public KeyStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "aauth-tests-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTrips()
    {
        var store = new KeyStore(_tempDir);
        var key = AAuthKey.Generate();

        store.Save("agent", key);
        var loaded = store.Load("agent");

        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(key.PublicKeyBytes, loaded.PublicKeyBytes);
        Assert.Equal(key.PrivateKeyBytes, loaded.PrivateKeyBytes);
    }

    [Fact]
    public void Exists_ReflectsFilesystem()
    {
        var store = new KeyStore(_tempDir);
        Assert.False(store.Exists("agent"));

        store.Save("agent", AAuthKey.Generate());
        Assert.True(store.Exists("agent"));
    }

    [Fact]
    public void LoadOrCreate_GeneratesOnce()
    {
        var store = new KeyStore(_tempDir);

        var first = store.LoadOrCreate("agent");
        var second = store.LoadOrCreate("agent");

        Assert.Equal(first.PublicKeyBytes, second.PublicKeyBytes);
    }

    [Fact]
    public void Load_MissingKey_Throws()
    {
        var store = new KeyStore(_tempDir);
        Assert.Throws<FileNotFoundException>(() => store.Load("missing"));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("../escape")]
    public void InvalidName_Throws(string name)
    {
        var store = new KeyStore(_tempDir);
        Assert.Throws<ArgumentException>(() => store.Exists(name));
    }
}
