using System;
using System.Threading.Tasks;
using AAuth.Server;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Maps the resource-managed (two-party) interaction poll endpoint.
/// </summary>
public static class AAuthInteractionEndpointExtensions
{
    /// <summary>
    /// Map <c>GET {PollPath}/{code}</c>: returns <c>202</c> while the user has not
    /// approved, and on approval issues the opaque access token bound to the polling
    /// agent via the <c>AAuth-Access</c> header (§Resource-Managed Authorization),
    /// then removes the pending entry (single-use). Place this route behind signature
    /// verification so the issued token is bound to a verified signature. The route
    /// pattern defaults to the configured <see cref="AAuthResourceManagedOptions.PollPath"/>.
    /// </summary>
    public static RouteHandlerBuilder MapAAuthInteractionPoll(
        this IEndpointRouteBuilder endpoints,
        string? pattern = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var options = endpoints.ServiceProvider.GetRequiredService<AAuthResourceManagedOptions>();
        pattern ??= $"{options.PollPath.TrimEnd('/')}/{{code}}";

        return endpoints.MapMethods(pattern, ["GET", "DELETE"], async (
            HttpContext ctx,
            string code,
            IInteractionPendingStore pending,
            IOpaqueTokenStore tokens) =>
        {
            var entry = pending.Get(code);
            if (entry is null)
            {
                return AAuthProblemDetails.Polling(AAuth.Errors.PollingErrorCode.InvalidCode);
            }

            // §Resource-Managed Authorization (spec, #aauth-access): the issued
            // AAuth-Access token is bound to the agent's verified signature, so the
            // poll MUST be verified. Fail closed when no verification ran (the route
            // is missing signature verification), and only the agent that parked the
            // interaction may claim it.
            var pollerJkt = ctx.GetAAuthVerification()?.Jkt;
            if (string.IsNullOrEmpty(pollerJkt))
            {
                return AAuth.Server.AAuthProblemDetails.SignatureFailure(AAuth.Errors.SignatureErrorCode.InvalidSignature);
            }
            if (!string.Equals(pollerJkt, entry.AgentJkt, StringComparison.Ordinal)
                || !string.Equals(entry.OwnerIssuer, ctx.GetAAuthVerification()?.Issuer, StringComparison.Ordinal)
                || !string.Equals(entry.OwnerAgent, ctx.GetAAuthVerification()?.Agent, StringComparison.Ordinal))
            {
                return AAuth.Server.AAuthProblemDetails.Create("denied", "interaction belongs to a different agent", statusCode: StatusCodes.Status403Forbidden);
            }

            return await entry.Lifecycle.ExecuteAsync(ctx, entry.Expiry, TimeProvider.System, async () =>
            {
                if (HttpMethods.IsDelete(ctx.Request.Method))
                {
                    entry.Lifecycle.Cancel();
                    return Results.NoContent();
                }
                if (entry.Denied) return AAuthProblemDetails.Create("denied", statusCode: 403);
                if (!entry.Approved)
                {
                    ctx.Response.Headers.RetryAfter = "1";
                    ctx.Response.Headers.CacheControl = "no-store";
                    return Results.Json(new { status = "pending" }, statusCode: StatusCodes.Status202Accepted);
                }

                // Atomically claim the approved interaction (single-use): only one
                // concurrent poll wins and issues a token; a loser sees it already gone.
                if (!pending.TryConsume(code, out var consumed))
                {
                    return AAuth.Server.AAuthProblemDetails.Polling(AAuth.Errors.PollingErrorCode.InvalidCode);
                }

                var grant = new OpaqueTokenInfo
                {
                    AgentJkt = pollerJkt,
                    Scope = consumed.Scope,
                    Account = consumed.Account,
                    Expiration = DateTimeOffset.UtcNow.Add(options.TokenTtl),
                };
                await ctx.IssueAAuthAccessAsync(tokens, grant, ctx.RequestAborted).ConfigureAwait(false);
                return Results.Ok(new { status = "complete" });
            });
        });
    }
}
