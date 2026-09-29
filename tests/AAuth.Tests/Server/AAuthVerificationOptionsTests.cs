using System;
using AAuth.Server.Verification;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthVerificationOptionsTests
{
    [Fact]
    public void Default_RequiresIssuerVerification()
    {
        Assert.Equal(["jwt"], new AAuthVerificationOptions().AcceptedSchemes);
    }

    [Fact]
    public void SignatureOnly_DisablesIssuerVerification()
    {
        var options = AAuthVerificationOptions.Generic();
        Assert.Contains("hwk", options.AcceptedSchemes);
        Assert.Same(TimeProvider.System, options.TimeProvider);
    }

    [Fact]
    public void SignatureOnly_ReturnsFreshInstances()
    {
        Assert.NotSame(AAuthVerificationOptions.Generic(), AAuthVerificationOptions.Generic());
    }

    [Fact]
    public void SignatureOnly_ForwardsTimeProvider()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var options = AAuthVerificationOptions.Generic(timeProvider);
        Assert.Same(timeProvider, options.TimeProvider);
    }
}
