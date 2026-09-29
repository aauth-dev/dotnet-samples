using System;
using System.Collections.Generic;
using AAuth.Crypto;
using AAuth.Server.Verification;

namespace AAuth.Server.Endpoints;

/// <summary>
/// Per-endpoint AAuth requirement attached as routing metadata by
/// <c>RequireAAuth</c> / <c>RequireAAuthSignature</c> and read by the
/// <c>UseAAuth</c> middleware to verify (and, for auth-token mode, challenge)
/// the matched endpoint.
/// </summary>
public sealed class AAuthEndpointRequirement
{
    /// <summary>Verification/challenge mode for this endpoint.</summary>
    public AAuthAccessMode Mode { get; init; } = AAuthAccessMode.RequireAuthToken;
    public IReadOnlyList<string> AcceptedSchemes { get; init; } = ["jwt"];

    /// <summary>Required scope (the challenge requests it; authorization enforces it).</summary>
    public string? Scope { get; init; }

    /// <summary>Required role, enforced from the auth token's <c>roles</c> claim.</summary>
    public string? Role { get; init; }

    /// <summary>Trust policy for this endpoint, replacing the resource's <see cref="AAuthServerOptions.Trust"/>.</summary>
    public IAAuthTrustPolicy? Trust { get; init; }
}

/// <summary>
/// Resource-level verification/challenge defaults for <c>UseAAuth</c>. The signing
/// key, key id, and resource identifier default from the DI-registered
/// <see cref="AAuth.Server.Metadata.AAuthResourceMetadataOptions"/> (so the only
/// per-call config a typical resource supplies is <em>trust</em>); the override
/// properties exist for the rare resource that needs them.
/// </summary>
public sealed class AAuthServerOptions
{
    /// <summary>Trust for auth-token, person-token and agent-token issuers. Open by default.</summary>
    public AAuthTrustOptions Trust { get; set; } = new();

    /// <summary>
    /// Resource-token audience for four-party (federated) resources: the
    /// resource's own Access Server. When null the audience is the PS that
    /// issued the presented person token (three-party).
    /// </summary>
    public string? AccessServer { get; set; }

    /// <summary>Override the resource identifier (default: DI metadata issuer).</summary>
    public string? ResourceIdentifier { get; set; }

    /// <summary>Override the challenge signing key (default: DI metadata first key).</summary>
    public IAAuthKey? ResourceSigningKey { get; set; }

    /// <summary>Override the challenge key id (default: DI metadata first kid).</summary>
    public string? ResourceKeyId { get; set; }
}
