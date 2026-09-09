using System;
using AAuth.Server.Verification;
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
        Assert.Null(options.Clock);
    }

    [Fact]
    public void SignatureOnly_ReturnsFreshInstances()
    {
        Assert.NotSame(AAuthVerificationOptions.Generic(), AAuthVerificationOptions.Generic());
    }

    [Fact]
    public void SignatureOnly_ForwardsClock()
    {
        var clock = () => DateTimeOffset.UnixEpoch;
        var options = AAuthVerificationOptions.Generic(clock);
        Assert.Same(clock, options.Clock);
    }
}
