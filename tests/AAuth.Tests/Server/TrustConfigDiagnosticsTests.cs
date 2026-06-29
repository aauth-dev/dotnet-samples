using System;
using System.Collections.Generic;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AAuth.Tests.Server;

/// <summary>
/// Phase 5 startup footgun guards: BOTTOM fail-fast (a trust policy configured with
/// issuer verification off is a contradiction) and the TOP warning (issuer
/// verification on with no policy ⇒ open by default).
/// </summary>
public class TrustConfigDiagnosticsTests
{
    [Fact(DisplayName = "Throws when a trust policy is set but issuer verification is off")]
    public void Throws_WhenAuthTrustConfigured_AndVerificationOff()
        => Assert.Throws<InvalidOperationException>(() => TrustConfigDiagnostics.Validate(
            logger: null, requireIssuerVerification: false,
            authTrustConfigured: true, agentTrustConfigured: false, "ctx"));

    [Fact(DisplayName = "Throws when agent-provider trust is set but issuer verification is off")]
    public void Throws_WhenAgentTrustConfigured_AndVerificationOff()
        => Assert.Throws<InvalidOperationException>(() => TrustConfigDiagnostics.Validate(
            logger: null, requireIssuerVerification: false,
            authTrustConfigured: false, agentTrustConfigured: true, "ctx"));

    [Fact(DisplayName = "Signature-only with no trust policy does not throw")]
    public void DoesNotThrow_SignatureOnly_NoTrust()
        => TrustConfigDiagnostics.Validate(
            logger: null, requireIssuerVerification: false,
            authTrustConfigured: false, agentTrustConfigured: false, "ctx");

    [Fact(DisplayName = "Warns when issuer verification is on and no auth-token policy is configured")]
    public void Warns_WhenOpenByDefault()
    {
        var log = new CapturingLogger();
        TrustConfigDiagnostics.Validate(log, requireIssuerVerification: true,
            authTrustConfigured: false, agentTrustConfigured: false, "ctx");
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact(DisplayName = "No warning when an explicit trust policy is configured")]
    public void DoesNotWarn_WhenPolicyConfigured()
    {
        var log = new CapturingLogger();
        TrustConfigDiagnostics.Validate(log, requireIssuerVerification: true,
            authTrustConfigured: true, agentTrustConfigured: false, "ctx");
        Assert.DoesNotContain(log.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact(DisplayName = "Open-federation warning fires when open, silent when configured")]
    public void WarnIfOpenFederation_Behaviour()
    {
        var open = new CapturingLogger();
        TrustConfigDiagnostics.WarnIfOpenFederation(open, trustConfigured: false, "ctx", "msg");
        Assert.Contains(open.Entries, e => e.Level == LogLevel.Warning);

        var configured = new CapturingLogger();
        TrustConfigDiagnostics.WarnIfOpenFederation(configured, trustConfigured: true, "ctx", "msg");
        Assert.DoesNotContain(configured.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact(DisplayName = "UseAAuthVerification throws on configured-but-ignored trust")]
    public void UseAAuthVerification_Throws_OnConfiguredButIgnoredTrust()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.UseAAuthVerification(
            new AAuthVerificationOptions
            {
                RequireIssuerVerification = false,
                TrustedAuthTokenIssuers = new HashSet<string> { "https://ps.example" },
            }));
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
