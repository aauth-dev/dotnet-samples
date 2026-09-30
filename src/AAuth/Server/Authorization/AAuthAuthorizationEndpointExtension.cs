using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.Authorization;

/// <summary>
/// Extension point for companion specifications that add request members to the
/// resource authorization endpoint.
/// </summary>
public interface IAAuthAuthorizationEndpointExtension
{
    /// <summary>
    /// Inspect the parsed authorization endpoint body and attach any typed
    /// extension state to the <paramref name="request"/>.
    /// </summary>
    ValueTask<AAuthAuthorizationExtensionResult> ReadAsync(
        HttpContext context,
        JsonObject body,
        AAuthAuthorizationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>The outcome of an authorization endpoint extension parse.</summary>
public sealed record AAuthAuthorizationExtensionResult(bool SatisfiesAuthorizationClaim = false);
