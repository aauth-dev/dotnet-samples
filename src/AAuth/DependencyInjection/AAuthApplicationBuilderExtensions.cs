using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
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
    /// <param name="configure">
    /// Adjusts the options for this pipeline after any DI configuration of
    /// <see cref="AAuthVerificationOptions"/>. The egress policy defaults to the registered
    /// <see cref="MetadataClient"/>'s.
    /// </param>
    public static IApplicationBuilder UseAAuthVerification(
        this IApplicationBuilder app,
        Action<AAuthVerificationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        var metadata = app.ApplicationServices.GetService<MetadataClient>();
        var options = AAuthOptionsResolver.Create(app.ApplicationServices,
            () => new AAuthVerificationOptions { EgressPolicy = metadata?.Policy ?? AAuthEgressPolicy.Production });
        configure?.Invoke(options);
        return app.UseAAuthVerificationCore(options);
    }

    internal static IApplicationBuilder UseAAuthVerificationCore(this IApplicationBuilder app, AAuthVerificationOptions resolvedOptions)
    {
        var resourceMetadata = app.ApplicationServices.GetService<AAuthResourceMetadataOptions>();
        resolvedOptions = AAuthResourceVerificationDefaults.Normalize(
            resolvedOptions, resourceMetadata?.AccessServer, app.ApplicationServices);
        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(
                app.ApplicationServices.GetService<JwksClient>(), app.ApplicationServices.GetService<MetadataClient>(),
                tokenVerifiers: app.ApplicationServices.GetServices<ISignatureTokenVerifier>(),
                services: app.ApplicationServices);
        var metadata = app.ApplicationServices.GetService<MetadataClient>();
        var jwks = app.ApplicationServices.GetService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();

        TrustConfigDiagnostics.Validate(
            app.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("AAuth.Verification"),
            authTrustConfigured: resolvedOptions.Trust.IsConfigured(AAuth.Server.AAuthTrustedParty.AuthTokenIssuer, app.ApplicationServices),
            agentTrustConfigured: resolvedOptions.Trust.IsConfigured(AAuth.Server.AAuthTrustedParty.AgentProvider, app.ApplicationServices),
            contextLabel: "UseAAuthVerification",
            accessServer: resourceMetadata?.AccessServer);

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
    /// <param name="configure">Adjusts the options after any DI configuration of <see cref="ChallengeOptions"/>.</param>
    public static IApplicationBuilder UseAAuthChallenge(
        this IApplicationBuilder app,
        Action<ChallengeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        var options = AAuthOptionsResolver.Create(app.ApplicationServices, () => new ChallengeOptions());
        configure?.Invoke(options);
        return app.UseAAuthChallengeCore(options);
    }

    internal static IApplicationBuilder UseAAuthChallengeCore(this IApplicationBuilder app, ChallengeOptions options)
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
    /// access. The request body carries <c>{ "scope": "…" }</c>, unless a
    /// registered companion extension such as R3 supplies a replacement
    /// authorization claim. The request MUST present a verified AAuth person
    /// token; otherwise the endpoint returns
    /// <c>AAuth-Requirement: requirement=person-token</c>.
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
            var verification = context.GetAAuthVerification();
            if (verification is not { TokenType: AAuthTokenType.PersonToken })
            {
                context.Response.Headers[AAuth.Headers.AAuthRequirementHeader.Name] =
                    AAuth.Headers.AAuthRequirementHeader.FormatPersonToken();
                return AAuth.Server.AAuthProblemDetails.Create("person_token_required",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!context.Request.HasJsonContentType())
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "Content-Type must be application/json", statusCode: StatusCodes.Status400BadRequest);
            }

            JsonObject? body;
            try
            {
                body = await context.Request
                    .ReadFromJsonAsync<JsonObject>(context.RequestAborted)
                    .ConfigureAwait(false);
            }
            catch (JsonException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "malformed JSON body", statusCode: StatusCodes.Status400BadRequest);
            }

            if (body is null)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "JSON body must be an object", statusCode: StatusCodes.Status400BadRequest);
            }

            var scopeNode = body["scope"];
            string? scope = null;
            if (scopeNode is not null)
            {
                if (scopeNode is not JsonValue scopeValue || !scopeValue.TryGetValue<string>(out scope))
                {
                    return AAuthProblemDetails.Create("invalid_request", "scope must be a string when present", statusCode: 400);
                }
            }

            var accountNode = body["account"];
            if (accountNode is not null && (accountNode is not JsonValue accountValue || !accountValue.TryGetValue<string>(out _)))
            {
                return AAuthProblemDetails.Create("invalid_request", "account must be a string when present", statusCode: 400);
            }

            var account = accountNode?.GetValue<string>();
            if (!AAuth.Tokens.AccountBinding.IsValid(account))
                return AAuthProblemDetails.Create("invalid_request", "account must be non-empty and contain no control characters", statusCode: 400);

            var request = new AAuthAuthorizationRequest(scope, verification) { Account = account };
            var hasExtensionClaim = false;
            foreach (var extension in context.RequestServices.GetServices<IAAuthAuthorizationEndpointExtension>())
            {
                AAuthAuthorizationExtensionResult result;
                try
                {
                    result = await extension.ReadAsync(context, body, request, context.RequestAborted)
                        .ConfigureAwait(false);
                }
                catch (AAuthAuthorizationExtensionException ex)
                {
                    return AAuthProblemDetails.Create(ex.Error, ex.Detail, statusCode: StatusCodes.Status400BadRequest);
                }

                hasExtensionClaim |= result.SatisfiesAuthorizationClaim;
            }

            if (string.IsNullOrWhiteSpace(scope) && !hasExtensionClaim)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "scope is required", statusCode: StatusCodes.Status400BadRequest);
            }

            return await handler(context, request).ConfigureAwait(false);
        }).RequireAAuthPersonToken();
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
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AAuth.Resource");
        AAuthServerRoles.RejectDevelopmentLoopbackInProduction(app.Services, "Resource", metadataOptions.EgressPolicy);
        AAuthServerRoles.WarnOnDevelopmentLoopback(app.Services, logger, "Resource", "Default", metadataOptions.EgressPolicy);

        // 1. Map well-known endpoints
        WellKnownEndpoints.MapAAuthResourceWellKnown(app, metadataOptions);

        // 2. Verification middleware
        app.UseAAuthVerificationCore(new AAuthVerificationOptions
        {
            EgressPolicy = metadataOptions.EgressPolicy,
            ResourceIdentifier = metadataOptions.Issuer,
            ExpectedAccount = pipelineOptions.AccountSelector,
            ExpectedAuthTokenDwk = metadataOptions.AccessServer is null
                ? AAuthConstants.DwkFiles.Person
                : AAuthConstants.DwkFiles.Access,
            Trust = pipelineOptions.Trust,
        });

        // 3. Challenge middleware (only if there's a signing key available)
        if (metadataOptions.SigningKeys is { Count: > 0 } signingKeys)
        {
            app.UseAAuthChallengeCore(new ChallengeOptions
            {
                EgressPolicy = metadataOptions.EgressPolicy,
                ResourceSigningKeys = signingKeys,
                ResourceIdentifier = metadataOptions.Issuer,
                AccessServer = metadataOptions.AccessServer,
                RequestedAccount = pipelineOptions.AccountSelector,
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
    /// <param name="configureVerification">Adjusts the verification options (signature + issuer verification).</param>
    /// <param name="configureChallenge">Adjusts the challenge options (access mode, resource key, scopes).</param>
    public static IApplicationBuilder UseAAuthIntermediary(
        this IApplicationBuilder app,
        Action<AAuthVerificationOptions>? configureVerification = null,
        Action<ChallengeOptions>? configureChallenge = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.UseAAuthVerification(configureVerification);
        app.UseAAuthChallenge(configureChallenge);
        return app;
    }
}
