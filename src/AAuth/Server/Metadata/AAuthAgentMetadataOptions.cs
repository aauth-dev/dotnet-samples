using System;
using System.Collections.Generic;
using AAuth.Crypto;

namespace AAuth.Server.Metadata;

/// <summary>
/// Configuration for the <c>/.well-known/aauth-agent.json</c> endpoint.
/// </summary>
public sealed class AAuthAgentMetadataOptions
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; set; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>HTTPS URL of this agent/agent provider (<c>issuer</c>). REQUIRED.</summary>
    public required string Issuer { get; set; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>. REQUIRED.</summary>
    public required AAuthSigningKeySet SigningKeys { get; set; }

    /// <summary>Optional human-readable name (<c>name</c>).</summary>
    public string? Name { get; set; }

    /// <summary>
    /// Optional Markdown <c>description</c> of the agent or its provider, for
    /// display to users (§Agent Provider Metadata). Implementations MUST sanitize
    /// the Markdown before rendering.
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

    /// <summary>Optional callback endpoint (<c>callback_endpoint</c>).</summary>
    public string? CallbackEndpoint { get; set; }

    /// <summary>Throw if any required field is unset/invalid.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("Issuer must be set.");
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer, EgressPolicy))
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        if (SigningKeys is null || SigningKeys.Count == 0)
            throw new InvalidOperationException("At least one signing key must be supplied.");
    }
}
