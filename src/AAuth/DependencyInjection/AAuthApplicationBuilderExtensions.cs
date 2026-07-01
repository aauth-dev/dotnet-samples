using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Builder;

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
                app.ApplicationServices.GetService<JwksClient>());
        var metadata = app.ApplicationServices.GetService<MetadataClient>();
        var jwks = app.ApplicationServices.GetService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();
        var resolvedOptions = options ?? new AAuthVerificationOptions();

        // Startup footgun guards (diagnostics only — no runtime policy change):
        // throw on a configured-but-ignored trust policy; warn on implicit-open.
        TrustConfigDiagnostics.Validate(
            app.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("AAuth.Verification"),
            resolvedOptions.RequireIssuerVerification,
            authTrustConfigured: resolvedOptions.TrustedAuthTokenIssuers is not null || resolvedOptions.IsTrustedAuthTokenIssuer is not null,
            agentTrustConfigured: resolvedOptions.TrustedAgentProviderIssuers is not null || resolvedOptions.IsTrustedAgentProviderIssuer is not null,
            contextLabel: "UseAAuthVerification");

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
    /// Map a resource <c>authorization_endpoint</c> (§Authorization Endpoint
    /// Request): a signed <c>POST</c> that the agent calls proactively to request
    /// access. The request body is <c>{ "scope": "…" }</c> (scope REQUIRED). The
    /// request MUST be AAuth-verified (place this route behind
    /// <see cref="UseAAuthVerification"/>); the agent token is read from the
    /// verified <c>Signature-Key</c>. The <paramref name="handler"/> runs the
    /// resource's authorization decision — returning, for example, a
    /// <c>202 + requirement=interaction</c> (via
    /// <c>HttpContext.InteractionRequiredAAuth</c>) or issuing a token (via
    /// <c>HttpContext.IssueAAuthAccessAsync</c>) — sharing one code path with the
    /// reactive endpoint.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="pattern">The route pattern (e.g. <c>/authorize</c>), matching the published <c>authorization_endpoint</c>.</param>
    /// <param name="handler">The authorization decision, given the verified request and requested scope.</param>
    public static RouteHandlerBuilder MapAAuthAuthorizationEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        Func<HttpContext, AAuthAuthorizationRequest, Task<IResult>> handler)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(pattern);
        ArgumentNullException.ThrowIfNull(handler);

        return endpoints.MapPost(pattern, async (HttpContext context) =>
        {
            // Require a verified AAuth signature (the agent token is in Signature-Key).
            var verification = context.GetAAuthVerification();
            if (verification is null)
            {
                return Results.Json(
                    new { error = "invalid_request" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // Body: { "scope": "a b c" } — scope is REQUIRED. Reject a non-JSON
            // content type up front: ReadFromJsonAsync would otherwise throw
            // InvalidOperationException (not JsonException) and surface as a 500.
            if (!context.Request.HasJsonContentType())
            {
                return Results.Json(
                    new { error = "invalid_request", error_description = "Content-Type must be application/json" },
                    statusCode: StatusCodes.Status415UnsupportedMediaType);
            }

            AuthorizationEndpointBody? body;
            try
            {
                body = await context.Request
                    .ReadFromJsonAsync<AuthorizationEndpointBody>(context.RequestAborted)
                    .ConfigureAwait(false);
            }
            catch (JsonException)
            {
                return Results.Json(
                    new { error = "invalid_request", error_description = "malformed JSON body" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (body is null || string.IsNullOrWhiteSpace(body.Scope))
            {
                return Results.Json(
                    new { error = "invalid_request", error_description = "scope is required" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var request = new AAuthAuthorizationRequest(body.Scope, verification);
            return await handler(context, request).ConfigureAwait(false);
        });
    }

    private sealed record AuthorizationEndpointBody(
        [property: JsonPropertyName("scope")] string? Scope);

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
            IsTrustedAuthTokenIssuer = pipelineOptions.IsTrustedAuthTokenIssuer,
            TrustedAgentProviderIssuers = pipelineOptions.TrustedAgentProviderIssuers,
            IsTrustedAgentProviderIssuer = pipelineOptions.IsTrustedAgentProviderIssuer,
        });

        // 3. Challenge middleware (only if there's a signing key available)
        if (metadataOptions.SigningKeys is { Count: > 0 } signingKeys)
        {
            // Use the first signing key for challenges
            string? kid = null;
            AAuth.Crypto.AAuthKey? key = null;
            foreach (var kvp in signingKeys)
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
