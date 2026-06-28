using System;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server;

/// <summary>
/// <see cref="HttpContext"/> helper for opening a resource-managed interaction.
/// </summary>
public static class AAuthResourceManagedHttpContextExtensions
{
    /// <summary>
    /// Open a resource-managed interaction for <paramref name="scope"/>: generate a
    /// spec-conformant code, park it on the <see cref="IInteractionPendingStore"/>,
    /// and return <c>202 + requirement=interaction</c> pointing the agent at the
    /// resource's consent page (<c>url</c>) and the poll <c>Location</c>. The
    /// resource's consent page records approval via
    /// <see cref="IInteractionPendingStore.Approve"/>; the poll endpoint
    /// (<c>MapAAuthInteractionPoll</c>) issues the opaque token on approval. Requires
    /// <c>AddAAuthResourceManaged</c> and a verified AAuth signature on the request.
    /// </summary>
    public static IResult RequireAAuthInteraction(this HttpContext context, string scope)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(scope);

        var store = context.RequestServices.GetRequiredService<IInteractionPendingStore>();
        var options = context.RequestServices.GetRequiredService<AAuthResourceManagedOptions>();

        var jkt = context.GetAAuthVerification()?.Jkt ?? "unknown";
        var entry = store.Park(scope, jkt, options.CodeTtl);
        var pollLocation = $"{options.PollPath.TrimEnd('/')}/{entry.Code}";

        var result = context.InteractionRequiredAAuth(options.ConsentUrl, entry.Code, pollLocation);
        // §Deferred Responses: Retry-After is REQUIRED on the 202.
        context.Response.Headers.RetryAfter = "0";
        return result;
    }
}
