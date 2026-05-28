using AAuth;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthHttpContextExtensionsTests
{
    [Fact]
    public void GetAAuthVerification_ReturnsNull_WhenMiddlewareNotRun()
    {
        var ctx = new DefaultHttpContext();
        Assert.Null(ctx.GetAAuthVerification());
    }

    [Fact]
    public void GetAAuthVerification_ReturnsResult_WhenSetInFeatures()
    {
        var ctx = new DefaultHttpContext();
        var expected = new AAuthVerificationResult
        {
            Level = AAuthLevel.Identified,
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = AAuthTokenType.AgentToken,
        };
        ctx.Features.Set(expected);

        var actual = ctx.GetAAuthVerification();
        Assert.Same(expected, actual);
    }

    [Fact]
    public void GetAAuthParsedKey_ReturnsNull_WhenMiddlewareNotRun()
    {
        var ctx = new DefaultHttpContext();
        Assert.Null(ctx.GetAAuthParsedKey());
    }

    [Fact]
    public void GetAAuthParsedKey_ReturnsParsedInfo_WhenSetInItems()
    {
        var ctx = new DefaultHttpContext();
        var expected = new SignatureKeyParser.ParsedSignatureKeyInfo
        {
            Scheme = AAuthConstants.Schemes.Hwk,
            Jkt = "test-thumbprint",
        };
        ctx.Items[AAuthVerificationMiddleware.ParsedInfoItemKey] = expected;

        var actual = ctx.GetAAuthParsedKey();
        Assert.Same(expected, actual);
    }

    [Fact]
    public void GetAAuthResult_ReturnsNull_WhenMiddlewareNotRun()
    {
        var ctx = new DefaultHttpContext();
        Assert.Null(ctx.GetAAuthResult());
    }

    [Fact]
    public void GetAAuthResult_ReturnsResult_WhenSetInItems()
    {
        var ctx = new DefaultHttpContext();
        var expected = new VerificationResult
        {
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = "aa-agent+jwt",
        };
        ctx.Items[AAuthVerificationMiddleware.ContextItemKey] = expected;

        var actual = ctx.GetAAuthResult();
        Assert.Same(expected, actual);
    }

    // -----------------------------------------------------------------------
    // GetAAuthTokenType
    // -----------------------------------------------------------------------

    [Fact]
    public void GetAAuthTokenType_ReturnsUnknown_WhenMiddlewareNotRun()
    {
        var ctx = new DefaultHttpContext();
        Assert.Equal(AAuthTokenType.Unknown, ctx.GetAAuthTokenType());
    }

    [Fact]
    public void GetAAuthTokenType_ReturnsTokenType_FromVerificationResult()
    {
        var ctx = new DefaultHttpContext();
        ctx.Features.Set(new AAuthVerificationResult
        {
            Level = AAuthLevel.Identified,
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = AAuthTokenType.AuthToken,
        });

        Assert.Equal(AAuthTokenType.AuthToken, ctx.GetAAuthTokenType());
    }

    // -----------------------------------------------------------------------
    // ChallengeAAuth
    // -----------------------------------------------------------------------

    [Fact]
    public void ChallengeAAuth_SetsHeaderAndReturns401()
    {
        var ctx = new DefaultHttpContext();
        var result = ctx.ChallengeAAuth("eyJ.test.sig");

        Assert.Equal(
            AAuthRequirementHeader.FormatAuthToken("eyJ.test.sig"),
            ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement].ToString());
    }

    // -----------------------------------------------------------------------
    // SetAAuthError
    // -----------------------------------------------------------------------

    [Fact]
    public void SetAAuthError_SetsHeader()
    {
        var ctx = new DefaultHttpContext();
        ctx.SetAAuthError("something went wrong");

        Assert.Equal("something went wrong",
            ctx.Response.Headers[AAuthConstants.Headers.AAuthError].ToString());
    }
}
