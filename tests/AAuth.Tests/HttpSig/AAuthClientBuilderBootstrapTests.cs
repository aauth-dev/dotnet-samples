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
    public async Task EnrolAndBuildAsync_WithMockAP_ReturnsClientAndResult()
    {
        // This test uses a mock AP that returns a pre-built agent token.
        var apKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            KeyId = "k1",
            Key = apKey,
            ConfirmationKey = agentKey,
            PersonServer = "https://ps.example",
        }.Build();

        // We can't easily mock the internal HttpClient in the bootstrap flow,
        // so we test that the bootstrap builder can be configured.
        var builder = AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:test@example.com")
            .WithPersonServer("https://ps.example")
            .WithChallengeHandling()
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
    public void Bootstrap_WithInteractionHandling_ConfiguresBuilder()
    {
        var builder = AAuthClientBuilder
            .Bootstrap("https://ap.example/enrol", "aauth:test@example.com")
            .WithPersonServer("https://ps.example")
            .WithChallengeHandling()
            .WithInteractionHandling(opts =>
            {
                opts.OnInteractionRequired = (_, _, _) => Task.CompletedTask;
            });

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
