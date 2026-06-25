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
        _verifier = verifier ?? new TokenVerifier();
    }

    /// <summary>
    /// Verify an auth token received from an AS per §Auth Token Delivery.
    /// </summary>
    /// <param name="authToken">The compact JWS auth token from the AS response.</param>
    /// <param name="expectedIssuer">The AS URL the PS sent the token request to (step 2).</param>
    /// <param name="expectedAudience">The resource URL from the resource token's <c>iss</c> (step 3).</param>
    /// <param name="expectedAgentId">The agent identifier that submitted the token request (step 4).</param>
    /// <param name="agentKey">The agent's signing key for <c>cnf.jwk</c> binding check (step 5).</param>
    /// <param name="expectedActContext">
    /// Optional act context for chain consistency check (step 6).
    /// When provided, verifies that the auth token's nested <c>act</c> claims match this context.
    /// For direct authorization: null (the auth token then carries no <c>act</c>).
    /// For call chaining: the upstream act that was submitted with the token request.
    /// </param>
    /// <param name="requestedScope">
    /// The scope from the resource token (step 7). When provided, verifies the auth token's
    /// scope is not broader than what was requested.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Validation result with verified token or error.</returns>
    public async Task<AuthTokenDeliveryResult> ValidateAsync(
        string authToken,
        string expectedIssuer,
        string expectedAudience,
        string expectedAgentId,
        IAAuthKey agentKey,
        JsonObject? expectedActContext = null,
        string? requestedScope = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(authToken);
        ArgumentException.ThrowIfNullOrEmpty(expectedIssuer);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(expectedAgentId);
        ArgumentNullException.ThrowIfNull(agentKey);

        try
        {
            // Steps 1, 3–5, 8–9: Reuse VerifyAuthTokenWithJwksAsync which performs:
            //  - JWT signature via JWKS discovery (step 1)
            //  - aud check (step 3)
            //  - agent claim check (step 5)
            //  - cnf.jwk binding against agentKey (step 4)
            //  - act OPTIONAL; when present act.agent is a valid agent id (step 6)
            //  - sub or scope present
            //  - scope narrowing
            var verified = await _verifier.VerifyAuthTokenWithJwksAsync(
                authToken,
                _metadata,
                _jwks,
                expectedAudience,
                agentKey,
                expectedAgentId,
                expectedMaxScope: requestedScope,
                cancellationToken: ct).ConfigureAwait(false);

            // Step 2: Verify iss matches the AS the PS sent the request to.
            if (verified.Issuer != expectedIssuer)
            {
                return new AuthTokenDeliveryResult
                {
                    IsValid = false,
                    Error = $"issuer_mismatch: expected '{expectedIssuer}', got '{verified.Issuer}'.",
                };
            }

            // Step 6 (full): when the caller supplies the expected upstream
            // delegation context, verify the nested act chain matches it. act is
            // OPTIONAL (§Delegation Chain); act.agent is the immediate upstream
            // agent and its own chain is nested as act.act.
            if (expectedActContext is not null)
            {
                var act = verified.Payload["act"] as JsonObject;
                var nestedAct = act?["act"] as JsonObject;

                if (!ActChainsMatch(nestedAct, expectedActContext))
                {
                    return new AuthTokenDeliveryResult
                    {
                        IsValid = false,
                        Error = "act_chain_mismatch: auth token act chain does not match the upstream delegation context.",
                    };
                }
            }

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

    /// <summary>
    /// Compare two act chain objects for structural equivalence.
    /// Checks that <c>agent</c> values match at each nesting level.
    /// </summary>
    private static bool ActChainsMatch(JsonObject? actual, JsonObject? expected)
    {
        if (actual is null && expected is null)
            return true;
        if (actual is null || expected is null)
            return false;

        var actualAgent = (string?)actual["agent"];
        var expectedAgent = (string?)expected["agent"];
        if (actualAgent != expectedAgent)
            return false;

        var actualNested = actual["act"] as JsonObject;
        var expectedNested = expected["act"] as JsonObject;
        return ActChainsMatch(actualNested, expectedNested);
    }
}
