using System;
using System.Threading.Tasks;
using AAuth;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
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

        var statusResult = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, statusResult.StatusCode);
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

    // -----------------------------------------------------------------------
    // Resource-managed AAuth-Access helpers
    // -----------------------------------------------------------------------

    private static DefaultHttpContext VerifiedContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Features.Set(new AAuthVerificationResult
        {
            Level = AAuthLevel.Pseudonymous,
            Scheme = AAuthConstants.Schemes.Hwk,
        });
        return ctx;
    }

    private static OpaqueTokenInfo SampleInfo() => new()
    {
        AgentJkt = "jkt-123",
        Scope = "inbox.read",
        Expiration = DateTimeOffset.UtcNow.AddMinutes(5),
    };

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsInfo_ForValidToken_AndCaches()
    {
        var store = new InMemoryOpaqueTokenStore();
        var token = await store.IssueAsync(SampleInfo());
        var ctx = VerifiedContext();
        ctx.Request.Headers.Authorization = $"AAuth {token}";

        var info = await ctx.ResolveAAuthAccessAsync(store);

        Assert.NotNull(info);
        Assert.Equal("jkt-123", info!.AgentJkt);
        Assert.True(ctx.TryGetAAuthAccess(out var cached));
        Assert.Same(info, cached);
    }

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsNull_WhenVerificationDidNotRun()
    {
        var store = new InMemoryOpaqueTokenStore();
        var token = await store.IssueAsync(SampleInfo());
        var ctx = new DefaultHttpContext(); // no AAuthVerificationResult feature
        ctx.Request.Headers.Authorization = $"AAuth {token}";

        Assert.Null(await ctx.ResolveAAuthAccessAsync(store));
    }

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsNull_WhenNoAuthorizationHeader()
    {
        var store = new InMemoryOpaqueTokenStore();
        var ctx = VerifiedContext();
        Assert.Null(await ctx.ResolveAAuthAccessAsync(store));
    }

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsNull_ForInvalidToken68()
    {
        var store = new InMemoryOpaqueTokenStore();
        var ctx = VerifiedContext();
        ctx.Request.Headers.Authorization = "AAuth not a token";
        Assert.Null(await ctx.ResolveAAuthAccessAsync(store));
    }

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsNull_ForUnknownToken()
    {
        var store = new InMemoryOpaqueTokenStore();
        var ctx = VerifiedContext();
        ctx.Request.Headers.Authorization = "AAuth deadbeefdeadbeefdeadbeef";
        Assert.Null(await ctx.ResolveAAuthAccessAsync(store));
    }

    [Fact]
    public async Task ResolveAAuthAccess_ReturnsNull_ForMultipleCredentials()
    {
        var store = new InMemoryOpaqueTokenStore();
        var token = await store.IssueAsync(SampleInfo());
        var ctx = VerifiedContext();
        ctx.Request.Headers.Authorization = new StringValues(new[] { $"AAuth {token}", "AAuth other" });
        Assert.Null(await ctx.ResolveAAuthAccessAsync(store));
    }

    [Fact]
    public async Task IssueAAuthAccess_SetsHeader_AndStoresValidatableToken()
    {
        var store = new InMemoryOpaqueTokenStore();
        var ctx = new DefaultHttpContext();

        var token = await ctx.IssueAAuthAccessAsync(store, SampleInfo());

        Assert.Equal(token, ctx.Response.Headers[AAuthConstants.Headers.AAuthAccess].ToString());
        Assert.True(AAuthAccessHeader.IsValidToken68(token));
        var validated = await store.ValidateAsync(token);
        Assert.NotNull(validated);
        Assert.Equal("inbox.read", validated!.Scope);
    }

    [Fact]
    public void InteractionRequiredAAuth_Sets202_Interaction_AndLocation()
    {
        var ctx = new DefaultHttpContext();
        var result = ctx.InteractionRequiredAAuth(
            "https://inbox.example/consent", "A1B2-C3D4", "https://inbox.example/pending/1");

        Assert.Equal(
            Interaction.Format("https://inbox.example/consent", "A1B2-C3D4"),
            ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement].ToString());
        Assert.Equal("https://inbox.example/pending/1", ctx.Response.Headers.Location.ToString());

        var statusResult = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status202Accepted, statusResult.StatusCode);
    }

    [Fact]
    public async Task ChallengeMiddleware_ResourceManaged_PassesThrough_EvenWithAgentToken()
    {
        var called = false;
        var mw = new AAuthChallengeMiddleware(
            _ => { called = true; return Task.CompletedTask; },
            new ChallengeOptions { AccessMode = AAuthAccessMode.ResourceManaged });
        var ctx = new DefaultHttpContext();
        ctx.Items[AAuthVerificationMiddleware.ContextItemKey] = new VerificationResult
        {
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = "aa-agent+jwt",
        };

        await mw.InvokeAsync(ctx);

        Assert.True(called);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }
}
