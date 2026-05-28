using System;
using System.Collections.Generic;
using AAuth.Crypto;
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
    /// Add AAuth verification middleware that performs HTTP signature PoP verification
    /// and (optionally) JWT issuer signature verification.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="options">Verification options. When null, uses default options (issuer verification enabled).</param>
    public static IApplicationBuilder UseAAuthVerification(
        this IApplicationBuilder app,
        AAuthVerificationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(
                app.ApplicationServices.GetService<JwksClient>(),
                app.ApplicationServices.GetService<MetadataClient>());
        var metadata = app.ApplicationServices.GetService<MetadataClient>();
        var jwks = app.ApplicationServices.GetService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();
        var resolvedOptions = options ?? new AAuthVerificationOptions();

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
            var mw = new AAuthVerificationMiddleware(
                next, verifier, resolver, metadata, jwks, resolvedOptions);
            return mw.InvokeAsync;
        });
    }

    /// <summary>
    /// Add the AAuth challenge middleware that automatically issues 401 challenges
    /// with resource tokens when the resource requires an auth token but only an
    /// agent token is presented. Must be registered AFTER <see cref="UseAAuthVerification"/>.
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

    /// <summary>
    /// Configure the full AAuth resource pipeline in one call: maps well-known endpoints,
    /// adds verification middleware, and adds challenge middleware. Uses the
    /// DI-registered <see cref="AAuthResourceMetadataOptions"/> for configuration.
    /// </summary>
    /// <remarks>
    /// Equivalent to calling <see cref="MapAAuthWellKnown"/>, <see cref="UseAAuthVerification"/>,
    /// and <see cref="UseAAuthChallenge"/> separately. For per-path customization, use the
    /// individual middleware methods instead.
    /// </remarks>
    /// <param name="app">The web application (both endpoint routing and middleware).</param>
    /// <param name="configure">Optional configuration for verification and challenge behavior.</param>
    public static WebApplication MapAAuthResource(
        this WebApplication app,
        Action<AAuthResourcePipelineOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        var metadataOptions = app.Services.GetRequiredService<AAuthResourceMetadataOptions>();
        var pipelineOptions = new AAuthResourcePipelineOptions();
        configure?.Invoke(pipelineOptions);

        // 1. Map well-known endpoints
        WellKnownEndpoints.MapAAuthResourceWellKnown(app, metadataOptions);

        // 2. Verification middleware
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            ResourceIdentifier = metadataOptions.Issuer,
            RequireIssuerVerification = pipelineOptions.RequireIssuerVerification,
            TrustedAuthTokenIssuers = pipelineOptions.TrustedAuthTokenIssuers,
            TrustedAgentProviderIssuers = pipelineOptions.TrustedAgentProviderIssuers,
        });

        // 3. Challenge middleware (only if there's a signing key available)
        if (metadataOptions.SigningKeys.Count > 0)
        {
            // Use the first signing key for challenges
            string? kid = null;
            AAuth.Crypto.AAuthKey? key = null;
            foreach (var kvp in metadataOptions.SigningKeys)
            {
                kid = kvp.Key;
                key = kvp.Value;
                break;
            }

            app.UseAAuthChallenge(new ChallengeOptions
            {
                ResourceSigningKey = key,
                ResourceKeyId = kid,
                ResourceIdentifier = metadataOptions.Issuer,
                AccessMode = pipelineOptions.AccessMode,
                DefaultScopes = pipelineOptions.DefaultScopes,
            });
        }

        return app;
    }

    /// <summary>
    /// Compose AAuth verification and challenge middleware for an intermediary
    /// resource that participates in call-chaining. Equivalent to calling
    /// <see cref="UseAAuthVerification"/> followed by <see cref="UseAAuthChallenge"/>
    /// with the supplied options.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="verificationOptions">Verification options (signature + issuer verification).</param>
    /// <param name="challengeOptions">Challenge options (access mode, resource key, scopes).</param>
    public static IApplicationBuilder UseAAuthIntermediary(
        this IApplicationBuilder app,
        AAuthVerificationOptions verificationOptions,
        ChallengeOptions challengeOptions)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(verificationOptions);
        ArgumentNullException.ThrowIfNull(challengeOptions);

        app.UseAAuthVerification(verificationOptions);
        app.UseAAuthChallenge(challengeOptions);
        return app;
    }
}
