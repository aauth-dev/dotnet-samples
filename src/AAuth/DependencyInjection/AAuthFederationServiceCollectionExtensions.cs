using System;
using System.Net.Http;
using AAuth;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for the four-party PS→AS federation client, so a Person Server
/// does not hand-wire the signed <see cref="AccessServerClient"/>, its transport,
/// and the <see cref="AuthTokenResponseValidator"/>.
/// </summary>
public static class AAuthFederationServiceCollectionExtensions
{
    /// <summary>
    /// The named <see cref="IHttpClientFactory"/> client the federation transport
    /// uses. Exposed as a typed handle so tests can redirect the PS→AS transport in
    /// process (e.g. <c>AddHttpClient(FederationHttpClientName).ConfigurePrimaryHttpMessageHandler(...)</c>)
    /// without a duplicated magic string.
    /// </summary>
    public const string FederationHttpClientName = "aauth-federation";

    /// <summary>
    /// Register the PS→AS federation client. The PS signs the token request with its
    /// own key via the <c>jwks_uri</c> scheme (the AS resolves the PS's public key
    /// from <c>{issuer}/.well-known/jwks.json</c>); the transport flows through the
    /// named <see cref="FederationHttpClientName"/> client. Resolves
    /// <see cref="MetadataClient"/> and <see cref="JwksClient"/> from DI. Registered
    /// via <c>TryAdd</c> so it stays overridable.
    /// </summary>
    public static IServiceCollection AddAAuthFederation(
        this IServiceCollection services,
        AAuthKey personServerKey,
        string personServerIssuer,
        string personServerKeyId)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(personServerKey);
        ArgumentException.ThrowIfNullOrEmpty(personServerIssuer);
        ArgumentException.ThrowIfNullOrEmpty(personServerKeyId);

        services.AddHttpClient(FederationHttpClientName);
        services.TryAddSingleton(sp =>
        {
            var metadata = sp.GetRequiredService<MetadataClient>();
            var jwks = sp.GetRequiredService<JwksClient>();
            var validator = new AuthTokenResponseValidator(metadata, jwks);
            var transport = sp.GetRequiredService<IHttpMessageHandlerFactory>()
                .CreateHandler(FederationHttpClientName);
            var signedClient = new AAuthClientBuilder(personServerKey)
                .UseJwksUri($"{personServerIssuer.TrimEnd('/')}/.well-known/jwks.json", personServerKeyId)
                .WithInnerHandler(transport)
                .Build();
            return new AccessServerClient(signedClient, metadata, validator);
        });
        return services;
    }
}
