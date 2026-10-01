using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;

namespace AAuth.Tokens;

/// <summary>
/// Result of auth token delivery verification.
/// </summary>
public sealed record AuthTokenDeliveryResult
{
    /// <summary>Whether the auth token is valid.</summary>
    public bool IsValid { get; init; }

    /// <summary>Error description when invalid.</summary>
    public string? Error { get; init; }

    /// <summary>The verified token's payload when valid.</summary>
    public TokenVerifier.VerifiedToken? Verified { get; init; }
}

/// <summary>
/// Validates auth token responses per §Auth Token Delivery steps 1–7.
/// Used by PS implementations to verify auth tokens received from an AS
/// before returning them to the agent.
/// </summary>
public sealed class AuthTokenResponseValidator
{
    private readonly MetadataClient _metadata;
    private readonly JwksClient _jwks;
    private readonly TokenVerifier _verifier;

    public AuthTokenResponseValidator(MetadataClient metadata, JwksClient jwks, TokenVerifier? verifier = null)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        _verifier = verifier ?? new TokenVerifier { EgressPolicy = metadata.Policy };
    }

    /// <summary>
    /// Verify an auth token received from an AS per §Auth Token Delivery: issued
    /// by the AS, for the resource, bound to the agent's key, naming the directed
    /// <c>sub</c> this PS minted and this PS as <c>ps</c>, no broader than the
    /// requested scope, and expiring no later than the presented token.
    /// </summary>
    /// <param name="authToken">The compact JWS auth token from the AS response.</param>
    /// <param name="expectedIssuer">The AS URL the PS sent the token request to.</param>
    /// <param name="expectedAudience">The resource URL from the resource token's <c>iss</c>.</param>
    /// <param name="expectedSubject">The directed <c>sub</c> from the resource token.</param>
    /// <param name="expectedPersonServer">This PS's identifier (<c>ps</c>).</param>
    /// <param name="agentKey">The agent's (or sub-agent's) key for the <c>cnf.jwk</c> check.</param>
    /// <param name="presentedTokenExpiresAt">The <c>exp</c> of the <c>presented_token</c> the PS sent.</param>
    /// <param name="requestedScope">The resource token's scope; the auth token's must be a subset.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="expectedAccount">The resource token's <c>account</c>, if any.</param>
    public async Task<AuthTokenDeliveryResult> ValidateAsync(
        string authToken,
        string expectedIssuer,
        string expectedAudience,
        string expectedSubject,
        string expectedPersonServer,
        IAAuthKey agentKey,
        DateTimeOffset presentedTokenExpiresAt,
        string? requestedScope = null,
        CancellationToken ct = default,
        string? expectedAccount = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(authToken);
        ArgumentException.ThrowIfNullOrEmpty(expectedIssuer);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(expectedSubject);
        ArgumentException.ThrowIfNullOrEmpty(expectedPersonServer);
        ArgumentNullException.ThrowIfNull(agentKey);

        try
        {
            var verified = await _verifier.VerifyAuthTokenWithJwksAsync(
                authToken,
                _metadata,
                _jwks,
                expectedAudience,
                agentKey,
                expectedDwk: AuthTokenBuilder.AccessDwk,
                expectedMaxScope: requestedScope,
                cancellationToken: ct).ConfigureAwait(false);

            if (!AccountBinding.Matches(expectedAccount, verified.Account))
                return new AuthTokenDeliveryResult { IsValid = false, Error = "account_mismatch: auth token differs from the resource request." };
            if (verified.Issuer != expectedIssuer)
                return new AuthTokenDeliveryResult { IsValid = false, Error = $"issuer_mismatch: expected '{expectedIssuer}', got '{verified.Issuer}'." };
            if (verified.Subject != expectedSubject || (string?)verified.Payload["ps"] != expectedPersonServer)
                return new AuthTokenDeliveryResult { IsValid = false, Error = "person_mismatch: auth token must name this PS and the resource token's sub." };
            if (verified.ExpiresAt > presentedTokenExpiresAt)
                return new AuthTokenDeliveryResult { IsValid = false, Error = "lifetime_mismatch: auth token outlives the presented token." };

            return new AuthTokenDeliveryResult
            {
                IsValid = true,
                Verified = verified,
            };
        }
        catch (TokenVerificationException ex)
        {
            return new AuthTokenDeliveryResult
            {
                IsValid = false,
                Error = ex.Message,
            };
        }
    }
}
