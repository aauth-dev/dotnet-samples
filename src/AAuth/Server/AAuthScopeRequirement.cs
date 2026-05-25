using Microsoft.AspNetCore.Authorization;

namespace AAuth.Server;

/// <summary>
/// Authorization requirement that demands a specific AAuth scope be present
/// in the verified token's <c>scope</c> claim.
/// </summary>
public sealed class AAuthScopeRequirement : IAuthorizationRequirement
{
    /// <summary>The required scope value.</summary>
    public string Scope { get; }

    /// <summary>Create a scope requirement.</summary>
    public AAuthScopeRequirement(string scope)
    {
        ArgumentException.ThrowIfNullOrEmpty(scope);
        Scope = scope;
    }
}
