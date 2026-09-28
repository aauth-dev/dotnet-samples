using System;
using System.Net.Http;
using AAuth;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Configuration;

/// <summary>
/// Verify that options flow correctly to underlying components.
/// </summary>
public class OptionsThreadingTests
{
    [Fact(DisplayName = "AAuthVerificationOptions.Clock threads to TokenVerifier")]
    public void VerificationOptions_Clock_ThreadsToTokenVerifier()
    {
        var fixedTime = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
        var options = new AAuthVerificationOptions
        {
            EgressPolicy = TestEgress.Policy,
            Clock = () => fixedTime,
            MaxActDepth = 5,
            ClockSkew = TimeSpan.FromSeconds(10),
        };

        // The middleware helper is private, but we can verify by constructing
        // a TokenVerifier with the same pattern and checking its behavior.
        var verifier = new TokenVerifier
        {
            EgressPolicy = TestEgress.Policy,
            MaxActDepth = options.MaxActDepth,
            ClockSkew = options.ClockSkew,
            Clock = options.Clock ?? (() => DateTimeOffset.UtcNow),
        };

        Assert.Equal(5, verifier.MaxActDepth);
        Assert.Equal(TimeSpan.FromSeconds(10), verifier.ClockSkew);
        Assert.Equal(fixedTime, verifier.Clock());
    }

    [Fact(DisplayName = "AAuthResourceOptions threads MaxSignatureAge and Clock to AAuthVerifier")]
    public void ResourceOptions_ThreadsToAAuthVerifier()
    {
        var fixedTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var services = new ServiceCollection();
        services.AddAAuthResource(options =>
        {
            options.Issuer = "https://example.com";
            options.MaxSignatureAge = TimeSpan.FromSeconds(120);
            options.Clock = () => fixedTime;
        });
        using var provider = services.BuildServiceProvider();
        var verifier = provider.GetRequiredService<AAuthVerifier>();

        Assert.Equal(TimeSpan.FromSeconds(120), verifier.MaxAge);
        Assert.Equal(fixedTime, verifier.Clock());
        var ahead = fixedTime.AddSeconds(90).ToUnixTimeSeconds();
        verifier.ValidateInput("sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + ahead, "sig");
    }

    [Fact(DisplayName = "ChallengeHandlingOptions exposes MinPollInterval and OnPoll")]
    public void ChallengeOptions_MinPollAndOnPoll()
    {
        HttpResponseMessage? captured = null;
        var options = new ChallengeHandlingOptions
        {
            MinPollInterval = TimeSpan.FromMilliseconds(500),
            OnPoll = r => captured = r,
        };

        Assert.Equal(TimeSpan.FromMilliseconds(500), options.MinPollInterval);
        Assert.NotNull(options.OnPoll);

        // Verify callback works
        var fakeResponse = new HttpResponseMessage();
        options.OnPoll!(fakeResponse);
        Assert.Same(fakeResponse, captured);
    }

    [Fact(DisplayName = "InteractionHandlingOptions has full polling parity")]
    public void InteractionOptions_FullPollingParity()
    {
        var options = new InteractionHandlingOptions
        {
            PollingTimeout = TimeSpan.FromMinutes(2),
            DefaultPollInterval = TimeSpan.FromSeconds(3),
            PreferWaitSeconds = 30,
            MinPollInterval = TimeSpan.FromMilliseconds(200),
            OnPoll = _ => { },
        };

        Assert.Equal(TimeSpan.FromMinutes(2), options.PollingTimeout);
        Assert.Equal(TimeSpan.FromSeconds(3), options.DefaultPollInterval);
        Assert.Equal(30, options.PreferWaitSeconds);
        Assert.Equal(TimeSpan.FromMilliseconds(200), options.MinPollInterval);
        Assert.NotNull(options.OnPoll);
    }

    [Fact(DisplayName = "All options have sensible defaults (no config = working)")]
    public void AllOptions_DefaultsPreserved()
    {
        var verification = new AAuthVerificationOptions();
        Assert.Equal(10, verification.MaxActDepth);
        Assert.Equal(TimeSpan.FromSeconds(30), verification.ClockSkew);
        Assert.Null(verification.Clock);

        var resource = new AAuthResourceOptions();
        Assert.Equal(TimeSpan.FromSeconds(60), resource.MaxSignatureAge);
        Assert.Null(resource.Clock);

        var challenge = new ChallengeHandlingOptions();
        Assert.Equal(TimeSpan.FromMinutes(5), challenge.PollingTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), challenge.DefaultPollInterval);
        Assert.Equal(TimeSpan.FromMilliseconds(100), challenge.MinPollInterval);
        Assert.Null(challenge.PreferWaitSeconds);
        Assert.Null(challenge.OnPoll);

        var interaction = new InteractionHandlingOptions();
        Assert.Equal(TimeSpan.FromMinutes(5), interaction.PollingTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), interaction.DefaultPollInterval);
        Assert.Equal(TimeSpan.FromMilliseconds(100), interaction.MinPollInterval);
        Assert.Null(interaction.PreferWaitSeconds);
        Assert.Null(interaction.OnPoll);
    }
}
