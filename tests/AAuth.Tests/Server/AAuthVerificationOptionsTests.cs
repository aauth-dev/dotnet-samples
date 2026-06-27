using System;
using AAuth.Server.Verification;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthVerificationOptionsTests
{
    [Fact]
    public void Default_RequiresIssuerVerification()
    {
        Assert.True(new AAuthVerificationOptions().RequireIssuerVerification);
    }

    [Fact]
    public void SignatureOnly_DisablesIssuerVerification()
    {
        var options = AAuthVerificationOptions.SignatureOnly();
        Assert.False(options.RequireIssuerVerification);
        Assert.Null(options.Clock);
    }

    [Fact]
    public void SignatureOnly_ReturnsFreshInstances()
    {
        Assert.NotSame(AAuthVerificationOptions.SignatureOnly(), AAuthVerificationOptions.SignatureOnly());
    }

    [Fact]
    public void SignatureOnly_ForwardsClock()
    {
        var clock = () => DateTimeOffset.UnixEpoch;
        var options = AAuthVerificationOptions.SignatureOnly(clock);
        Assert.Same(clock, options.Clock);
    }
}
