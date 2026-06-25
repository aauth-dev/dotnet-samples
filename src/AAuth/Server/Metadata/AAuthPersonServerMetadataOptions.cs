using System;
using System.Collections.Generic;
using AAuth.Crypto;

namespace AAuth.Server.Metadata;

/// <summary>
/// Configuration for the <c>/.well-known/aauth-person.json</c> endpoint.
/// </summary>
public sealed class AAuthPersonServerMetadataOptions
{
    /// <summary>HTTPS URL of this person server (<c>issuer</c>). REQUIRED.</summary>
    public required string Issuer { get; init; }

    /// <summary>Token endpoint URL (<c>token_endpoint</c>). REQUIRED.</summary>
    public required string TokenEndpoint { get; init; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>. REQUIRED.</summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>Optional human-readable name (<c>name</c>).</summary>
    public string? Name { get; init; }

    /// <summary>
    /// Optional Markdown <c>description</c> of the person server, for display to
    /// users (§Person Server Metadata). Implementations MUST sanitize the Markdown
    /// before rendering.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>Optional logo URL (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; init; }

    /// <summary>Optional dark-background logo URL (<c>logo_dark_uri</c>).</summary>
    public string? LogoDarkUri { get; init; }

    /// <summary>Optional developer-documentation URL (<c>documentation_uri</c>).</summary>
    public string? DocumentationUri { get; init; }

    /// <summary>Optional terms-of-service URL (<c>tos_uri</c>).</summary>
    public string? TosUri { get; init; }

    /// <summary>Optional privacy-policy URL (<c>policy_uri</c>).</summary>
    public string? PolicyUri { get; init; }

    /// <summary>Optional mission endpoint (<c>mission_endpoint</c>).</summary>
    public string? MissionEndpoint { get; init; }

    /// <summary>Optional permission endpoint (<c>permission_endpoint</c>).</summary>
    public string? PermissionEndpoint { get; init; }

    /// <summary>Optional audit endpoint (<c>audit_endpoint</c>).</summary>
    public string? AuditEndpoint { get; init; }

    /// <summary>Optional interaction endpoint (<c>interaction_endpoint</c>).</summary>
    public string? InteractionEndpoint { get; init; }

    /// <summary>Optional revocation endpoint (<c>revocation_endpoint</c>).</summary>
    public string? RevocationEndpoint { get; init; }

    /// <summary>Optional scopes supported (<c>scopes_supported</c>).</summary>
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>Throw if any required field is unset/invalid.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("Issuer must be set.");
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer))
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        if (string.IsNullOrWhiteSpace(TokenEndpoint))
            throw new InvalidOperationException("TokenEndpoint must be set.");
        if (SigningKeys is null || SigningKeys.Count == 0)
            throw new InvalidOperationException("At least one signing key must be supplied.");
    }
}
