using System.Collections.Generic;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;

namespace AAuth;

/// <summary>
/// Options for the unified <see cref="AAuthApplicationBuilderExtensions.MapAAuthResource"/>
/// pipeline, controlling verification and challenge behavior.
/// </summary>
public sealed class AAuthResourcePipelineOptions
{
    /// <summary>
    /// When true, the middleware verifies the JWT issuer's signature via JWKS discovery.
    /// Default: <c>true</c>.
    /// </summary>
    public bool RequireIssuerVerification { get; set; } = true;

    /// <summary>
    /// Access mode controlling whether the middleware challenges or passes through.
    /// Default: <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthAccessMode AccessMode { get; set; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>
    /// Optional allow-list of trusted Person Server / Access Server issuers (for <c>aa-auth+jwt</c>).
    /// When null, any issuer whose JWKS is resolvable is accepted.
    /// </summary>
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; set; }

    /// <summary>
    /// Optional allow-list of trusted Agent Provider issuers (for <c>aa-agent+jwt</c>).
    /// When null, any issuer whose JWKS is resolvable is accepted.
    /// </summary>
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; set; }

    /// <summary>
    /// Default scopes to request in the resource token. Space-separated.
    /// </summary>
    public string? DefaultScopes { get; set; }
}
