using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

/// <summary>
/// Authorization handler that evaluates <see cref="AAuthScopeRequirement"/>
/// against the <see cref="AAuthVerificationResult"/> stored in <c>HttpContext.Features</c>.
/// </summary>
public sealed class AAuthScopeHandler : AuthorizationHandler<AAuthScopeRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>Create the handler.</summary>
    public AAuthScopeHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AAuthScopeRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var result = httpContext?.Features.Get<AAuthVerificationResult>();

        // Scopes are only meaningful on auth tokens (Authorized level). A
        // pseudonymous or identified token must never satisfy a scope policy
        // even if it somehow carries a stray scope claim.
        if (result is not null
            && result.Level == AAuthLevel.Authorized
            && result.Scopes.Contains(requirement.Scope))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
