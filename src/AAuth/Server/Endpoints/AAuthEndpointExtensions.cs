using System;
using System.Linq;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.Challenge;
using AAuth.Server.Endpoints;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Declarative per-route AAuth: attach an <see cref="AAuthEndpointRequirement"/> to
/// an endpoint with <c>RequireAAuth</c> / <c>RequireAAuthSignature</c>, then verify
/// (and challenge) every matched endpoint with a single <c>UseAAuth</c> middleware
/// placed after <c>UseRouting</c>.
/// </summary>
public static class AAuthEndpointExtensions
{
    /// <summary>
    /// Require an auth token (optionally a <paramref name="scope"/> and/or
    /// <paramref name="role"/>) for this endpoint. Attaches the verification +
    /// challenge metadata and an inline authorization policy — no named scope
    /// policy string to keep in sync.
    /// </summary>
    /// <param name="trust">Trust policy for this endpoint only, replacing the resource-wide trust.</param>
    public static RouteHandlerBuilder RequireAAuth(
        this RouteHandlerBuilder builder,
        string? scope = null,
        string? role = null,
        IAAuthTrustPolicy? trust = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.RequireAuthToken,
            Scope = scope,
            Role = role,
            Trust = trust,
        });
        builder.RequireAuthorization(policy =>
        {
            policy.AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName).RequireAuthenticatedUser();
            policy.RequireClaim(AAuthAuthenticationHandler.LevelClaimType, AAuthLevel.Authorized.ToString());
            if (!string.IsNullOrEmpty(scope))
            {
                policy.AddRequirements(new AAuthScopeRequirement(scope));
            }
            if (!string.IsNullOrEmpty(role))
            {
                policy.RequireRole(role);
            }
        });
        return builder;
    }

    /// <summary>
    /// Verify an agent or auth token and its HTTP signature, with no auth-token
    /// challenge. When <paramref name="identified"/> is
    /// true, also require at least the Identified level (an agent token).
    /// </summary>
    public static RouteHandlerBuilder RequireAAuthSignature(
        this RouteHandlerBuilder builder,
        bool identified = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new AAuthEndpointRequirement { Mode = AAuthAccessMode.IdentityOnly });
        if (identified)
        {
            builder.RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
                .RequireAuthenticatedUser()
                .RequireClaim(AAuthAuthenticationHandler.LevelClaimType,
                    AAuthLevel.Identified.ToString(), AAuthLevel.Authorized.ToString()));
        }
        return builder;
    }

    /// <summary>
    /// Require a verified AAuth person token and challenge missing or wrong AAuth
    /// token types with <c>requirement=person-token</c>.
    /// </summary>
    public static RouteHandlerBuilder RequireAAuthPersonToken(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new AAuthEndpointRequirement { Mode = AAuthAccessMode.PersonTokenRequired });
        return builder;
    }

    public static RouteHandlerBuilder RequireGenericSignature(this RouteHandlerBuilder builder, bool identified = false)
    {
        builder.RequireAAuthSignature(identified);
        builder.WithMetadata(new AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.IdentityOnly,
            AcceptedSchemes = ["jwt", "hwk", "jkt-jwt", "jwks_uri", "jwks", "self-jwt"],
        });
        return builder;
    }

    /// <summary>
    /// Add the single AAuth pipeline middleware. Place it AFTER <c>UseRouting()</c>
    /// and before <c>UseAuthentication()</c>/<c>UseAuthorization()</c>: it reads each
    /// matched endpoint's <see cref="AAuthEndpointRequirement"/> and runs the
    /// existing verification (and, for auth-token mode, challenge) middleware for it.
    /// Endpoints without the metadata (well-known, index, browser consent pages) pass
    /// through unverified. Resource signing key / issuer default from the DI-registered
    /// <see cref="AAuthResourceMetadataOptions"/>; <paramref name="configure"/> supplies
    /// trust (and, for federated resources, the AS audience).
    /// </summary>
    public static IApplicationBuilder UseAAuth(
        this IApplicationBuilder app,
        Action<AAuthServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        var opts = new AAuthServerOptions();
        configure?.Invoke(opts);

        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(app.ApplicationServices.GetService<JwksClient>(), app.ApplicationServices.GetService<MetadataClient>(),
                tokenVerifiers: app.ApplicationServices.GetServices<ISignatureTokenVerifier>(),
                services: app.ApplicationServices);
        var metadataClient = app.ApplicationServices.GetService<MetadataClient>();
        var jwks = app.ApplicationServices.GetService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();
        var resourceMetadata = app.ApplicationServices.GetService<AAuthResourceMetadataOptions>();

        // Challenge defaults from the DI-registered resource metadata (G3): the
        // resource identifier and its signing keys. UseAAuth callers override
        // only when they must.
        var resourceIdentifier = opts.ResourceIdentifier ?? resourceMetadata?.Issuer;
        var effectiveAccessServer = opts.AccessServer ?? resourceMetadata?.AccessServer;
        var signingKeys = opts.ResourceSigningKeys
            ?? (resourceMetadata?.SigningKeys is { Count: > 0 } keys ? keys : null);
        var authVerifyOptions = AAuthResourceVerificationDefaults.Normalize(
            new AAuthVerificationOptions
            {
                EgressPolicy = resourceMetadata?.EgressPolicy ?? metadataClient?.Policy ?? AAuth.Discovery.AAuthEgressPolicy.Production,
                ResourceIdentifier = resourceIdentifier,
                Trust = opts.Trust,
            },
            effectiveAccessServer,
            app.ApplicationServices);
        TrustConfigDiagnostics.Validate(
            app.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("AAuth"),
            authTrustConfigured: authVerifyOptions.Trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer, app.ApplicationServices),
            agentTrustConfigured: authVerifyOptions.Trust.IsConfigured(AAuthTrustedParty.AgentProvider, app.ApplicationServices),
            contextLabel: "UseAAuth",
            accessServer: effectiveAccessServer);

        return app.Use((HttpContext context, RequestDelegate next) =>
        {
            // Fail-closed: if routing has not run, GetEndpoint() is null for every
            // request and protected endpoints would silently serve unverified. Throw
            // loudly instead. (IEndpointFeature is set by UseRouting.)
            if (context.Features.Get<IEndpointFeature>() is null)
            {
                throw new InvalidOperationException(
                    "UseAAuth() must be placed after UseRouting() so endpoint metadata is available.");
            }

            var req = context.GetEndpoint()?.Metadata.GetMetadata<AAuthEndpointRequirement>();
            if (req is null)
            {
                return next(context);
            }

            // Fail-closed: an auth-token endpoint without a resource identifier cannot
            // bind the auth token's `aud` to this resource, so the verifier would skip
            // the audience check and admit a token minted for a different resource
            // (§Request-Context Binding `aud`). Refuse to serve such a misconfiguration.
            if (req.Mode == AAuthAccessMode.RequireAuthToken && string.IsNullOrEmpty(resourceIdentifier))
            {
                throw new InvalidOperationException(
                    "An endpoint requires an auth token but no resource identifier is configured. " +
                    "Set AAuthResourceOptions.Issuer (via AddAAuthResource) or AAuthServerOptions.ResourceIdentifier " +
                    "so the auth token's `aud` is verified against this resource.");
            }

            if (jtiStore is not null)
            {
                context.Items[AAuthVerificationMiddleware.JtiStoreItemKey] = jtiStore;
            }

            if (req.Mode == AAuthAccessMode.PersonTokenRequired
                && !context.Request.Headers.ContainsKey(AAuthConstants.Headers.SignatureKey))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
                return Task.CompletedTask;
            }

            var verifyOptions = req.Mode == AAuthAccessMode.RequireAuthToken
                ? authVerifyOptions
                : new AAuthVerificationOptions
                {
                    EgressPolicy = resourceMetadata?.EgressPolicy ?? metadataClient?.Policy ?? AAuth.Discovery.AAuthEgressPolicy.Production,
                    AcceptedSchemes = req.AcceptedSchemes,
                    ResourceIdentifier = resourceIdentifier,
                    Trust = opts.Trust,
                };

            RequestDelegate afterVerify = req.Mode switch
            {
                AAuthAccessMode.RequireAuthToken => ctx => new AAuthChallengeMiddleware(next, new ChallengeOptions
                {
                    EgressPolicy = resourceMetadata?.EgressPolicy ?? metadataClient?.Policy ?? AAuth.Discovery.AAuthEgressPolicy.Production,
                    AccessMode = AAuthAccessMode.RequireAuthToken,
                    ResourceSigningKeys = signingKeys,
                    ResourceIdentifier = resourceIdentifier,
                    AccessServer = effectiveAccessServer,
                    DefaultScopes = req.Scope,
                }).InvokeAsync(ctx),
                AAuthAccessMode.PersonTokenRequired => async ctx =>
                {
                    if (ctx.GetAAuthVerification() is { TokenType: AAuthTokenType.PersonToken })
                    {
                        await next(ctx).ConfigureAwait(false);
                        return;
                    }

                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    ctx.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
                },
                _ => next,
            };

            var verifyMw = new AAuthVerificationMiddleware(
                afterVerify, verifier, resolver, metadataClient, jwks, verifyOptions);
            return verifyMw.InvokeAsync(context);
        });
    }
}
