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
    /// Add the AAuth full verification middleware that performs BOTH HTTP signature
    /// PoP verification AND JWT issuer signature verification in a single pass.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="options">Full verification options. When null, uses default options (issuer verification enabled, no issuer allow-list).</param>
    public static IApplicationBuilder UseAAuthFullVerification(
        this IApplicationBuilder app,
        FullVerificationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(app.ApplicationServices.GetService<JwksClient>());
        var metadata = app.ApplicationServices.GetRequiredService<MetadataClient>();
        var jwks = app.ApplicationServices.GetRequiredService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();
        var resolvedOptions = options ?? new FullVerificationOptions();

        if (jtiStore is not null)
        {
            app.Use(async (context, next) =>
            {
                context.Items[AAuthVerificationMiddleware.JtiStoreItemKey] = jtiStore;
                await next();
            });
        }

        return app.Use(next =>
        {
            var mw = new AAuthFullVerificationMiddleware(
                next, verifier, resolver, metadata, jwks, resolvedOptions);
            return mw.InvokeAsync;
        });
    }

    /// <summary>
    /// Add the AAuth challenge middleware that automatically issues 401 challenges
    /// with resource tokens when the resource requires an auth token but only an
    /// agent token is presented. Must be registered AFTER <see cref="UseAAuthFullVerification"/>.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="options">Challenge options configuring access mode, resource key, and scopes.</param>
    public static IApplicationBuilder UseAAuthChallenge(
        this IApplicationBuilder app,
        ChallengeOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        return app.Use(next =>
        {
            var mw = new AAuthChallengeMiddleware(next, options);
            return mw.InvokeAsync;
        });
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
