namespace AAuth.Server.CallChaining;

/// <summary>
/// Feature set on <see cref="Microsoft.AspNetCore.Http.HttpContext.Features"/>
/// by <see cref="AAuthVerificationMiddleware"/> when the inbound request carries
/// a verified <c>aa-auth+jwt</c> token. Provides direct access to the raw auth
/// token string without re-parsing <c>Signature-Key</c>.
/// </summary>
/// <remarks>
/// Used by <see cref="CallChainingRouter"/> and the call-chaining builder
/// extension (<c>WithCallChaining(HttpContext)</c>) to read the upstream auth
/// token for downstream exchange.
/// </remarks>
public sealed class UpstreamAuthTokenFeature
{
    /// <summary>Create the feature with the verified auth token.</summary>
    /// <param name="token">The raw compact-JWS auth token string.</param>
    public UpstreamAuthTokenFeature(string token)
    {
        Token = token;
    }

    /// <summary>The verified upstream auth token (compact JWS).</summary>
    public string Token { get; }
}
