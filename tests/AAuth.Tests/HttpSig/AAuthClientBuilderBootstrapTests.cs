using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthClientBuilderBootstrapTests
{
    [Fact]
    public void Bootstrap_ReturnsBootstrapBuilder()
    {
        var builder = AAuthClientBuilder.Bootstrap(
            "https://ap.example/enrol",
            "aauth:test@example.com");

        Assert.NotNull(builder);
    }

    [Fact]
    public void Bootstrap_WithPersonServer_ConfiguresBuilder()
    {
        var builder = AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:test@example.com")
            .WithPersonServer("https://ps.example")
            .WithKeyStore(new InMemoryKeyStore());

        Assert.NotNull(builder);
    }

    [Fact]
    public void Bootstrap_WithAttestor_ConfiguresBuilder()
    {
        var builder = AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:test@example.com")
            .WithAttestor(new NoopAttestor())
            .WithKeyStore(new InMemoryKeyStore());

        Assert.NotNull(builder);
    }

    [Fact]
    public void Bootstrap_NullEndpoint_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            AAuthClientBuilder.Bootstrap("", "aauth:test@example.com"));
    }

    [Fact]
    public void Bootstrap_NullAgentId_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            AAuthClientBuilder.Bootstrap("https://ap.example/enrol", ""));
    }
}

/// <summary>Expose the NoopAttestor for testing.</summary>
internal sealed class NoopAttestor : IPlatformAttestor
{
    public Task<string> AttestAsync(string keyId, CancellationToken ct = default)
        => Task.FromResult(string.Empty);
}
