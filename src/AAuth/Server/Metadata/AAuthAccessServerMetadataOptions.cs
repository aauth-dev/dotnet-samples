using System;
using System.Collections.Generic;
using AAuth.Crypto;

namespace AAuth.Server.Metadata;

/// <summary>
/// Configuration for the <c>/.well-known/aauth-access.json</c> endpoint.
/// </summary>
public sealed class AAuthAccessServerMetadataOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>HTTPS URL of this access server (<c>issuer</c>). REQUIRED.</summary>
    public required string Issuer { get; set; }

    /// <summary>Auth token endpoint URL (<c>auth_token_endpoint</c>). REQUIRED.</summary>
    public required string AuthTokenEndpoint { get; set; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>. REQUIRED.</summary>
    public required AAuthSigningKeySet SigningKeys { get; set; }

    /// <summary>Optional human-readable name (<c>name</c>).</summary>
    public string? Name { get; set; }

    /// <summary>
    /// Optional Markdown <c>description</c> of the access server, for display to
    /// users (§Access Server Metadata). Implementations MUST sanitize the Markdown
    /// before rendering.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>Optional logo URL (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; set; }

    /// <summary>Optional dark-background logo URL (<c>logo_dark_uri</c>).</summary>
    public string? LogoDarkUri { get; set; }

    /// <summary>Optional developer-documentation URL (<c>documentation_uri</c>).</summary>
    public string? DocumentationUri { get; set; }

    /// <summary>Optional terms-of-service URL (<c>tos_uri</c>).</summary>
    public string? TosUri { get; set; }

    /// <summary>Optional privacy-policy URL (<c>policy_uri</c>).</summary>
    public string? PolicyUri { get; set; }

    /// <summary>Optional revocation endpoint (<c>revocation_endpoint</c>).</summary>
    public string? RevocationEndpoint { get; set; }

    /// <summary>Throw if any required field is unset/invalid.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("Issuer must be set.");
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer, EgressPolicy))
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        AAuthMetadataUrl.ValidateRequired(EgressPolicy, AuthTokenEndpoint, AAuthUrlKind.Endpoint, Issuer, nameof(AuthTokenEndpoint));
        AAuthMetadataUrl.ValidateRequired(EgressPolicy, $"{Issuer.TrimEnd('/')}/.well-known/jwks.json",
            AAuthUrlKind.Jwks, Issuer, "JwksUri");
        if (SigningKeys is null || SigningKeys.Count == 0)
            throw new InvalidOperationException("At least one signing key must be supplied.");
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, LogoUri, AAuthUrlKind.Informational, Issuer, nameof(LogoUri));
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, LogoDarkUri, AAuthUrlKind.Informational, Issuer, nameof(LogoDarkUri));
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, DocumentationUri, AAuthUrlKind.Informational, Issuer, nameof(DocumentationUri));
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, TosUri, AAuthUrlKind.Informational, Issuer, nameof(TosUri));
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, PolicyUri, AAuthUrlKind.Informational, Issuer, nameof(PolicyUri));
        AAuthMetadataUrl.ValidateOptional(EgressPolicy, RevocationEndpoint, AAuthUrlKind.Endpoint, Issuer, nameof(RevocationEndpoint));
    }
}
