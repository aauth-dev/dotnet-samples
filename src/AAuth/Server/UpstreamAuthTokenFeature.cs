using System;

namespace AAuth.Server;

/// <summary>
/// HttpContext feature set by <see cref="AAuthVerificationMiddleware"/>
/// when the inbound request carries a verified <c>aa-auth+jwt</c>
/// auth token. Exposed so an intermediary endpoint (acting as agent
/// for downstream resources) can hand the upstream auth token to
/// <c>AAuthClientBuilder.WithCallChaining(...)</c> without re-parsing
/// the <c>Signature-Key</c> header.
/// </summary>
/// <remarks>
/// Spec: this is the caller's auth token that the intermediary must
/// pass as <c>upstream_token</c> in any downstream token-exchange
/// request, per §Call Chaining and §Upstream Token Verification.
/// </remarks>
public sealed class UpstreamAuthTokenFeature
{
    /// <summary>Create the feature.</summary>
    public UpstreamAuthTokenFeature(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        Token = token;
    }

    /// <summary>The compact <c>aa-auth+jwt</c> presented by the caller.</summary>
    public string Token { get; }
}
