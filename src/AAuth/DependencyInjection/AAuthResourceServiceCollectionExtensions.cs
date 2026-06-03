using System;
using System.Net.Http;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering AAuth resource server services via DI.
/// </summary>
public static class AAuthResourceServiceCollectionExtensions
{
    /// <summary>
    /// Register AAuth resource server services: verifier, key resolver,
    /// JTI store, and well-known metadata options.
    /// </summary>
    public static IServiceCollection AddAAuthResource(
        this IServiceCollection services,
        Action<AAuthResourceOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AAuthResourceOptions();
        configure(options);

        if (string.IsNullOrEmpty(options.Issuer))
            throw new InvalidOperationException("AAuthResourceOptions.Issuer must be set.");

        // Register AAuthVerifier as singleton.
        services.TryAddSingleton(sp => new AAuthVerifier
        {
            MaxAge = options.MaxSignatureAge,
            MaxFutureSkew = options.MaxFutureSkew,
            Clock = options.Clock ?? (() => DateTimeOffset.UtcNow),
        });

        // Register JwksClient (singleton) for key resolution.
        services.TryAddSingleton(sp =>
        {
            var httpClient = new HttpClient();
            return new JwksClient(httpClient);
        });

        // Register ISignatureKeyResolver.
        if (options.KeyResolver is not null)
        {
            services.TryAddSingleton(options.KeyResolver);
        }
        else
        {
            services.TryAddSingleton<ISignatureKeyResolver>(sp =>
            {
                var jwksClient = sp.GetRequiredService<JwksClient>();
                var metadataClient = sp.GetService<MetadataClient>();
                return new DefaultSignatureKeyResolver(jwksClient, metadataClient);
            });
        }

        // Register IJtiStore if replay detection is enabled.
        if (options.EnableReplayDetection)
        {
            services.TryAddSingleton<IJtiStore, InMemoryJtiStore>();
        }

        // Register the well-known metadata options for UseAAuthVerification / MapAAuthWellKnown.
        var metadataOptions = new AAuthResourceMetadataOptions
        {
            Issuer = options.Issuer,
            SigningKeys = options.SigningKeys,
            ClientName = options.ClientName,
            ScopeDescriptions = options.ScopeDescriptions,
        };
        services.TryAddSingleton(metadataOptions);

        return services;
    }

    /// <summary>
    /// Register the AAuth authentication scheme that maps
    /// <see cref="AAuthVerificationResult"/> to <c>HttpContext.User</c>.
    /// </summary>
    /// <remarks>
    /// Call this after <c>AddAuthentication()</c> or as the default scheme.
    /// The handler reads from <c>HttpContext.Features</c>, which is populated
    /// by <see cref="AAuthVerificationMiddleware"/>.
    /// </remarks>
    public static IServiceCollection AddAAuthAuthentication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAuthentication(AAuthAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, AAuthAuthenticationHandler>(
                AAuthAuthenticationHandler.SchemeName, _ => { });

        return services;
    }

    /// <summary>
    /// Register AAuth authorization policies and the scope handler.
    /// </summary>
    /// <remarks>
    /// Registers these built-in policies:
    /// <list type="bullet">
    /// <item><c>AAuth.Authenticated</c> — any verified AAuth identity (Pseudonymous+)</item>
    /// <item><c>AAuth.Identified</c> — requires at least Identified level (agent token)</item>
    /// <item><c>AAuth.Authorized</c> — requires Authorized level (auth token)</item>
    /// </list>
    /// For scope-based policies, use <see cref="AddAAuthScopePolicy"/>.
    /// </remarks>
    public static IServiceCollection AddAAuthAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, AAuthScopeHandler>());

        services.AddAuthorizationBuilder()
            .AddPolicy("AAuth.Authenticated", policy =>
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName))
            .AddPolicy("AAuth.Identified", policy =>
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
                    .RequireClaim(AAuthAuthenticationHandler.LevelClaimType,
                        AAuthLevel.Identified.ToString(),
                        AAuthLevel.Authorized.ToString()))
            .AddPolicy("AAuth.Authorized", policy =>
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
                    .RequireClaim(AAuthAuthenticationHandler.LevelClaimType,
                        AAuthLevel.Authorized.ToString()));

        return services;
    }

    /// <summary>
    /// Add a named authorization policy that requires a specific AAuth scope.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="policyName">The policy name (e.g. <c>"AAuth.Scope.data:read"</c>).</param>
    /// <param name="requiredScope">The required scope value.</param>
    public static IServiceCollection AddAAuthScopePolicy(
        this IServiceCollection services,
        string policyName,
        string requiredScope)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        ArgumentException.ThrowIfNullOrEmpty(requiredScope);

        services.AddAuthorizationBuilder()
            .AddPolicy(policyName, policy =>
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
                    .AddRequirements(new AAuthScopeRequirement(requiredScope)));

        return services;
    }

    /// <summary>
    /// Add a named authorization policy that requires a specific AAuth role.
    /// Roles are mapped from the auth token's <c>roles</c> claim ([@!RFC9068])
    /// to <see cref="System.Security.Claims.ClaimTypes.Role"/> by
    /// <see cref="AAuthAuthenticationHandler"/>, so this is backed by the
    /// standard ASP.NET Core <c>RequireRole</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="policyName">The policy name (e.g. <c>"AAuth.Role.whoami-admin"</c>).</param>
    /// <param name="requiredRole">The required role value.</param>
    public static IServiceCollection AddAAuthRolePolicy(
        this IServiceCollection services,
        string policyName,
        string requiredRole)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        ArgumentException.ThrowIfNullOrEmpty(requiredRole);

        services.AddAuthorizationBuilder()
            .AddPolicy(policyName, policy =>
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
                    .RequireClaim(AAuthAuthenticationHandler.LevelClaimType,
                        AAuthLevel.Authorized.ToString())
                    .RequireRole(requiredRole));

        return services;
    }
}
