using System;
using System.Collections.Generic;
using AAuth.Crypto;

namespace AAuth.Server;

/// <summary>
/// Configuration for the <c>/.well-known/aauth-access.json</c> endpoint.
/// </summary>
public sealed class AAuthAccessServerMetadataOptions
{
    /// <summary>HTTPS URL of this access server (<c>issuer</c>). REQUIRED.</summary>
    public required string Issuer { get; init; }

    /// <summary>Token endpoint URL (<c>token_endpoint</c>). REQUIRED.</summary>
    public required string TokenEndpoint { get; init; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>. REQUIRED.</summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>Optional revocation endpoint (<c>revocation_endpoint</c>).</summary>
    public string? RevocationEndpoint { get; init; }

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
