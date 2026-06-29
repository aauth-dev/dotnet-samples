using System;
using System.Linq;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.Challenge;
using AAuth.Server.Endpoints;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
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
    public static RouteHandlerBuilder RequireAAuth(
        this RouteHandlerBuilder builder,
        string? scope = null,
        string? role = null,
        bool missionAware = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.RequireAuthToken,
            Scope = scope,
            Role = role,
            MissionAware = missionAware,
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
    /// Verify the agent's signature only — identity-based or resource-managed
    /// access, with no auth-token challenge. When <paramref name="identified"/> is
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

        // Startup footgun guards (diagnostics only): throw on a configured-but-
        // ignored trust policy; warn when auth-token endpoints are implicitly open.
        TrustConfigDiagnostics.Validate(
            app.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("AAuth"),
            opts.RequireIssuerVerification,
            authTrustConfigured: opts.TrustedAuthTokenIssuers is not null || opts.IsTrustedAuthTokenIssuer is not null,
            agentTrustConfigured: opts.TrustedAgentProviderIssuers is not null || opts.IsTrustedAgentProviderIssuer is not null,
            contextLabel: "UseAAuth");

        var verifier = app.ApplicationServices.GetRequiredService<AAuthVerifier>();
        var resolver = app.ApplicationServices.GetService<ISignatureKeyResolver>()
            ?? new DefaultSignatureKeyResolver(app.ApplicationServices.GetService<JwksClient>());
        var metadataClient = app.ApplicationServices.GetService<MetadataClient>();
        var jwks = app.ApplicationServices.GetService<JwksClient>();
        var jtiStore = app.ApplicationServices.GetService<IJtiStore>();
        var resourceMetadata = app.ApplicationServices.GetService<AAuthResourceMetadataOptions>();

        // Challenge defaults from the DI-registered resource metadata (G3): the
        // resource identifier and the first signing key. UseAAuth callers override
        // only when they must.
        var resourceIdentifier = opts.ResourceIdentifier ?? resourceMetadata?.Issuer;
        var signingKey = opts.ResourceSigningKey;
        var signingKid = opts.ResourceKeyId;
        if (signingKey is null && resourceMetadata?.SigningKeys is { Count: > 0 } keys)
        {
            var first = keys.First();
            signingKid = first.Key;
            signingKey = first.Value;
        }

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

            var verifyOptions = req.Mode == AAuthAccessMode.RequireAuthToken
                ? new AAuthVerificationOptions
                {
                    ResourceIdentifier = resourceIdentifier,
                    RequireIssuerVerification = opts.RequireIssuerVerification,
                    TrustedAuthTokenIssuers = opts.TrustedAuthTokenIssuers,
                    IsTrustedAuthTokenIssuer = opts.IsTrustedAuthTokenIssuer,
                    TrustedAgentProviderIssuers = opts.TrustedAgentProviderIssuers,
                    IsTrustedAgentProviderIssuer = opts.IsTrustedAgentProviderIssuer,
                }
                : AAuthVerificationOptions.SignatureOnly();

            RequestDelegate afterVerify = req.Mode == AAuthAccessMode.RequireAuthToken
                ? ctx => new AAuthChallengeMiddleware(next, new ChallengeOptions
                {
                    AccessMode = AAuthAccessMode.RequireAuthToken,
                    ResourceSigningKey = signingKey,
                    ResourceKeyId = signingKid,
                    ResourceIdentifier = resourceIdentifier,
                    PersonServerAudience = opts.PersonServerAudience,
                    DefaultScopes = req.Scope,
                    MissionAware = req.MissionAware,
                }).InvokeAsync(ctx)
                : next;

            var verifyMw = new AAuthVerificationMiddleware(
                afterVerify, verifier, resolver, metadataClient, jwks, verifyOptions);
            return verifyMw.InvokeAsync(context);
        });
    }
}
