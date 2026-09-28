using System.Collections.Generic;
using AAuth.Server;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;

namespace AAuth;

/// <summary>
/// Options for the unified <see cref="AAuthApplicationBuilderExtensions.MapAAuthResource"/>
/// pipeline, controlling verification and challenge behavior.
/// </summary>
public sealed class AAuthResourcePipelineOptions
{
    public Func<Microsoft.AspNetCore.Http.HttpContext, string?>? AccountSelector { get; set; }
    /// <summary>
    /// Access mode controlling whether the middleware challenges or passes through.
    /// Default: <see cref="AAuthAccessMode.RequireAuthToken"/>.
    /// </summary>
    public AAuthAccessMode AccessMode { get; set; } = AAuthAccessMode.RequireAuthToken;

    /// <summary>
    /// Optional allow-list of trusted Person Server / Access Server issuers (for <c>aa-auth+jwt</c>).
    /// When null, any verifiable issuer is accepted; an empty set denies all.
    /// </summary>
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; set; }

    /// <summary>
    /// Optional trust policy for auth-token issuers, AND-composed with
    /// <see cref="TrustedAuthTokenIssuers"/>.
    /// </summary>
    public Func<string, bool>? IsTrustedAuthTokenIssuer { get; set; }

    /// <summary>
    /// Optional allow-list of Person Servers whose person tokens are accepted. When
    /// unset, person tokens follow <see cref="TrustedAuthTokenIssuers"/>; set it in
    /// four-party, where the AS rather than the PS issues auth tokens.
    /// </summary>
    public IReadOnlySet<string>? TrustedPersonServers { get; set; }

    /// <summary>Optional trust policy for person-token issuers, AND-composed with <see cref="TrustedPersonServers"/>.</summary>
    public Func<string, bool>? IsTrustedPersonServer { get; set; }

    /// <summary>
    /// Optional allow-list of trusted Agent Provider issuers (for <c>aa-agent+jwt</c>).
    /// When null, any issuer whose JWKS is resolvable is accepted.
    /// </summary>
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; set; }

    /// <summary>
    /// Optional trust policy for Agent Provider issuers, AND-composed with
    /// <see cref="TrustedAgentProviderIssuers"/>.
    /// </summary>
    public Func<string, bool>? IsTrustedAgentProviderIssuer { get; set; }

    /// <summary>
    /// Default scopes to request in the resource token. Space-separated.
    /// </summary>
    public string? DefaultScopes { get; set; }
}
