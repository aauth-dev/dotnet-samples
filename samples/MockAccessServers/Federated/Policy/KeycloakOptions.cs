namespace MockAccessServer.Policy;

/// <summary>
/// Configuration for <see cref="KeycloakAccessPolicy"/>. Bound from the
/// <c>AccessServer:Keycloak</c> configuration section.
/// </summary>
public sealed class KeycloakOptions
{
    /// <summary>
    /// The realm authority, e.g. <c>http://localhost:8080/realms/aauth</c>.
    /// OIDC + UMA endpoints are derived from this.
    /// </summary>
    public string Authority { get; set; } = "http://localhost:8080/realms/aauth";

    /// <summary>The confidential client id the AS adapter authenticates as.</summary>
    public string ClientId { get; set; } = "aauth-access-server";

    /// <summary>The confidential client secret.</summary>
    public string ClientSecret { get; set; } = "";

    /// <summary>
    /// The Authorization-Services (resource server) client id used as the
    /// <c>audience</c> of the <c>uma-ticket</c> grant. Defaults to
    /// <see cref="ClientId"/> when unset.
    /// </summary>
    public string? ResourceServerAudience { get; set; }

    /// <summary>
    /// The Keycloak resource name registered for the protected resource;
    /// combined with the requested scope into the <c>permission</c>
    /// (<c>RESOURCE#SCOPE</c>). The demo registers a single <c>wallet</c>
    /// resource.
    /// </summary>
    public string ResourceName { get; set; } = "wallet";

    /// <summary>The OIDC authorization endpoint.</summary>
    public string AuthorizationEndpoint => $"{Authority.TrimEnd('/')}/protocol/openid-connect/auth";

    /// <summary>The OIDC/UMA token endpoint (handles code exchange and the uma-ticket grant).</summary>
    public string TokenEndpoint => $"{Authority.TrimEnd('/')}/protocol/openid-connect/token";
}
