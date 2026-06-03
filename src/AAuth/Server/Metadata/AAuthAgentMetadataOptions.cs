using System;
using System.Collections.Generic;
using AAuth.Crypto;

namespace AAuth.Server.Metadata;

/// <summary>
/// Configuration for the <c>/.well-known/aauth-agent.json</c> endpoint.
/// </summary>
public sealed class AAuthAgentMetadataOptions
{
    /// <summary>HTTPS URL of this agent/agent provider (<c>issuer</c>). REQUIRED.</summary>
    public required string Issuer { get; init; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>. REQUIRED.</summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>Optional human-readable name (<c>client_name</c>).</summary>
    public string? ClientName { get; init; }

    /// <summary>Optional logo URL (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; init; }

    /// <summary>Optional callback endpoint (<c>callback_endpoint</c>).</summary>
    public string? CallbackEndpoint { get; init; }

    /// <summary>Optional login endpoint (<c>login_endpoint</c>).</summary>
    public string? LoginEndpoint { get; init; }

    /// <summary>Throw if any required field is unset/invalid.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("Issuer must be set.");
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer))
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        if (SigningKeys is null || SigningKeys.Count == 0)
            throw new InvalidOperationException("At least one signing key must be supplied.");
    }
}
