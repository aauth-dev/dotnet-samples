using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.DependencyInjection;

/// <summary>
/// Extension methods for configuring AAuth verification middleware and
/// well-known endpoints from DI-registered services.
/// </summary>
public static class AAuthApplicationBuilderExtensions
{
    /// <summary>
    /// Add AAuth signature verification middleware, resolving the verifier,
    /// key resolver, and JTI store from DI.
    /// </summary>
    public static IApplicationBuilder UseAAuthVerification(this IApplicationBuilder app)
    {
        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(app.ApplicationServices.GetService<JwksClient>());
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();

        return AAuthVerificationMiddlewareExtensions.UseAAuthVerification(
            app, verifier, jtiStore, resolver);
    }

    /// <summary>
    /// Map the <c>/.well-known/aauth-resource.json</c> and <c>/.well-known/jwks.json</c>
    /// endpoints from DI-registered <see cref="AAuthResourceMetadataOptions"/>.
    /// </summary>
    public static IEndpointRouteBuilder MapAAuthWellKnown(this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider.GetRequiredService<AAuthResourceMetadataOptions>();
        return WellKnownEndpoints.MapAAuthResourceWellKnown(endpoints, options);
    }
}
