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

        if (result is not null && result.Scopes.Contains(requirement.Scope))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
