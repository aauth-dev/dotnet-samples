using System;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class EnrolledBuilderTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private const string RefreshEndpoint = "http://localhost:5200/refresh";
    private const string LocalKeyHandle = "my-agent-key";
    private const string PersonServer = "http://localhost:5100";

    [Fact]
    public void Enrolled_throws_on_null_key()
    {
        Assert.Throws<ArgumentNullException>(() => AAuthClientBuilder.Enrolled(null!));
    }

    [Fact]
    public void RefreshingFrom_throws_on_null_endpoint()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.RefreshingFrom(null!, LocalKeyHandle));
    }

    [Fact]
    public void RefreshingFrom_throws_on_empty_endpoint()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentException>(() => builder.RefreshingFrom("", LocalKeyHandle));
    }

    [Fact]
    public void RefreshingFrom_throws_on_null_keyHandle()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.RefreshingFrom(RefreshEndpoint, null!));
    }

    [Fact]
    public void RefreshingFrom_throws_on_empty_keyHandle()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentException>(() => builder.RefreshingFrom(RefreshEndpoint, ""));
    }

    [Fact]
    public void Build_throws_without_RefreshingFrom()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Enrolled_with_RefreshingFrom_builds_client()
    {
        // This builds a client with token refresh configured (will attempt refresh on first request)
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void Enrolled_with_challenge_handling_builds_client()
    {
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .WithChallengeHandling(PersonServer)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void Enrolled_with_two_key_mode_builds_client()
    {
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .WithRefreshMode(RefreshMode.TwoKey, "http://localhost:5200")
            .WithChallengeHandling(PersonServer)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void WithKeyStore_throws_on_null()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.WithKeyStore(null!));
    }

    /// <summary>Simple in-memory key store for testing.</summary>
    private sealed class InMemoryKeyStore : IKeyStore
    {
        private readonly AAuthKey _key;
        public InMemoryKeyStore(AAuthKey key) => _key = key;
        public Task<IAAuthKey?> LoadAsync(string handle, System.Threading.CancellationToken ct = default)
            => Task.FromResult<IAAuthKey?>(_key);
        public Task StoreAsync(string handle, IAAuthKey key, System.Threading.CancellationToken ct = default)
            => Task.CompletedTask;
        public Task DeleteAsync(string handle, System.Threading.CancellationToken ct = default)
            => Task.CompletedTask;
        public Task<string[]> ListAsync(System.Threading.CancellationToken ct = default)
            => Task.FromResult(Array.Empty<string>());
    }
}
