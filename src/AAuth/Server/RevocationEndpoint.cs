using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Server;

/// <summary>
/// Extension methods to map a POST /revoke endpoint for AAuth token revocation.
/// </summary>
public static class RevocationEndpoint
{
    /// <summary>
    /// Map the revocation endpoint. Accepts form-encoded <c>token</c> (a JTI)
    /// and marks it as revoked in the <see cref="IJtiStore"/>.
    /// </summary>
    public static IEndpointRouteBuilder MapAAuthRevocationEndpoint(
        this IEndpointRouteBuilder endpoints,
        IJtiStore jtiStore,
        string path = "/revoke")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(jtiStore);

        endpoints.MapPost(path, async (HttpContext context) =>
        {
            if (!context.Request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Content-Type must be application/x-www-form-urlencoded" });
            }

            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var token = form["token"].ToString();

            if (string.IsNullOrEmpty(token))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "token parameter is required" });
            }

            await jtiStore.RevokeAsync(token, context.RequestAborted);

            // Per RFC 7009: return 200 even if the token was not found.
            return Results.Ok();
        });

        return endpoints;
    }
}
