using System.Collections.Generic;
using System.Threading.Tasks;
using AAuth;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthScopeHandlerTests
{
    private static async Task<bool> EvaluateAsync(AAuthVerificationResult? result, string requiredScope)
    {
        var httpContext = new DefaultHttpContext();
        if (result is not null)
        {
            httpContext.Features.Set(result);
        }

        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        var handler = new AAuthScopeHandler(accessor);
        var requirement = new AAuthScopeRequirement(requiredScope);
        var context = new AuthorizationHandlerContext(
            new[] { requirement },
            user: new System.Security.Claims.ClaimsPrincipal(),
            resource: null);

        await ((IAuthorizationHandler)handler).HandleAsync(context);
        return context.HasSucceeded;
    }

    [Fact]
    public async Task Succeeds_WhenAuthorizedTokenCarriesRequiredScope()
    {
        var result = new AAuthVerificationResult
        {
            Level = AAuthLevel.Authorized,
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = AAuthTokenType.AuthToken,
            Scopes = new HashSet<string> { "whoami" },
        };

        Assert.True(await EvaluateAsync(result, "whoami"));
    }

    [Fact]
    public async Task Fails_WhenAuthorizedTokenMissingRequiredScope()
    {
        // A token scoped only for `whoami` must NOT satisfy a `whoami:admin`
        // policy — scope membership is exact, not hierarchical.
        var result = new AAuthVerificationResult
        {
            Level = AAuthLevel.Authorized,
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = AAuthTokenType.AuthToken,
            Scopes = new HashSet<string> { "whoami" },
        };

        Assert.False(await EvaluateAsync(result, "whoami:admin"));
    }

    [Fact]
    public async Task Fails_WhenIdentifiedTokenCarriesStrayScopeClaim()
    {
        // Closes the PoP-only bypass: a non-Authorized token must never
        // satisfy a scope policy even if it somehow carries a scope claim.
        var result = new AAuthVerificationResult
        {
            Level = AAuthLevel.Identified,
            Scheme = AAuthConstants.Schemes.Jwt,
            TokenType = AAuthTokenType.AgentToken,
            Scopes = new HashSet<string> { "whoami" },
        };

        Assert.False(await EvaluateAsync(result, "whoami"));
    }

    [Fact]
    public async Task Fails_WhenPseudonymousTokenCarriesStrayScopeClaim()
    {
        var result = new AAuthVerificationResult
        {
            Level = AAuthLevel.Pseudonymous,
            Scheme = AAuthConstants.Schemes.Hwk,
            TokenType = AAuthTokenType.AgentToken,
            Scopes = new HashSet<string> { "whoami" },
        };

        Assert.False(await EvaluateAsync(result, "whoami"));
    }

    [Fact]
    public async Task Fails_WhenNoVerificationResult()
    {
        Assert.False(await EvaluateAsync(result: null, "whoami"));
    }
}
