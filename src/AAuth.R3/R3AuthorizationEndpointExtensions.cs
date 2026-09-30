using System.Text.Json.Nodes;
using AAuth.R3.Model;
using AAuth.Server;
using AAuth.Server.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3;

/// <summary>Server-side R3 authorization endpoint integration.</summary>
public static class R3AuthorizationEndpointExtensions
{
    private const string FeatureKey = "AAuth.R3.AuthorizationOperations";

    /// <summary>
    /// Register the R3 authorization endpoint extension so a scope-less
    /// <c>r3_operations</c> request can satisfy the AAuth authorization endpoint.
    /// </summary>
    public static IServiceCollection AddAAuthR3AuthorizationEndpoint(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IAAuthAuthorizationEndpointExtension, R3AuthorizationEndpointExtension>();
        return services;
    }

    /// <summary>Gets the typed R3 operations parsed from the authorization request.</summary>
    public static R3Operations? GetR3Operations(this AAuthAuthorizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Features.TryGetValue(FeatureKey, out var value) ? value as R3Operations : null;
    }

    private sealed class R3AuthorizationEndpointExtension : IAAuthAuthorizationEndpointExtension
    {
        public ValueTask<AAuthAuthorizationExtensionResult> ReadAsync(
            HttpContext context,
            JsonObject body,
            AAuthAuthorizationRequest request,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(body);
            ArgumentNullException.ThrowIfNull(request);
            if (body["r3_operations"] is null)
            {
                return ValueTask.FromResult(new AAuthAuthorizationExtensionResult());
            }

            try
            {
                request.Features[FeatureKey] = R3Request.ReadOperations(body);
            }
            catch (InvalidOperationException ex)
            {
                throw new AAuthAuthorizationExtensionException("invalid_r3_operations", ex.Message, ex);
            }

            return ValueTask.FromResult(new AAuthAuthorizationExtensionResult(SatisfiesAuthorizationClaim: true));
        }
    }
}
