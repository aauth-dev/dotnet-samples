using AAuth.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace SampleApp;

/// <summary>
/// Mini resource server endpoints demonstrating AAuth server-side features:
/// full verification middleware, auto-challenge, and authorization policies.
/// </summary>
public static class ResourceEndpoints
{
    public static void MapResourceEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api");

        // Identity-only endpoint: accepts any verified agent (no auth token needed).
        group.MapGet("/whoami", (HttpContext ctx) =>
        {
            var result = ctx.Features.Get<AAuthVerificationResult>();
            if (result is null)
                return Results.Json(new { error = "no_verification" }, statusCode: 401);

            return Results.Json(new
            {
                agent = result.Agent,
                scheme = result.Scheme,
                level = result.Level.ToString(),
                scopes = result.Scopes,
                issuerVerified = result.IssuerVerified,
            });
        });

        // Authorized endpoint: requires auth token with specific scope.
        group.MapGet("/data", (HttpContext ctx) =>
        {
            var result = ctx.Features.Get<AAuthVerificationResult>();
            if (result is null)
                return Results.Json(new { error = "no_verification" }, statusCode: 401);

            return Results.Json(new
            {
                message = "Access granted",
                agent = result.Agent,
                scopes = result.Scopes,
                tokenType = result.TokenType,
            });
        });
    }
}
