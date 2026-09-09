using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Identifiers;

namespace AAuth.Tokens;

/// <summary>
/// Result of upstream token validation.
/// </summary>
public sealed record UpstreamTokenValidationResult
{
    /// <summary>Whether the upstream token is valid.</summary>
    public bool IsValid { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Error description when invalid.</summary>
    public string? Error { get; init; }
    public AAuth.Errors.SignatureErrorCode FailureCode { get; init; } = AAuth.Errors.SignatureErrorCode.InvalidJwt;

    /// <summary>The upstream token's own <c>act</c> claim (its delegation chain),
    /// or <see langword="null"/> if the upstream token was a direct authorization.
    /// Combine with <see cref="Agent"/> via <see cref="ActChainBuilder.BuildNestedAct"/>
    /// to compose the downstream <c>act</c> node per §Upstream Token Verification step 4.</summary>
    public JsonObject? UpstreamAct { get; init; }

    /// <summary>The upstream token's issuer.</summary>
    public string? Issuer { get; init; }

    /// <summary>The upstream token's <c>dwk</c> claim, which authoritatively
    /// identifies the issuer's role: <c>aauth-access.json</c> when issued by an
    /// AS (four-party), <c>aauth-person.json</c> when issued by a PS (three-party).
    /// Verified during validation, since the issuer's signing key was resolved at
    /// <c>{iss}/.well-known/{dwk}</c>.</summary>
    public string? IssuerDwk { get; init; }

    /// <summary>The upstream token's agent identifier.</summary>
    public string? Agent { get; init; }

    /// <summary>The upstream token's subject.</summary>
    public string? Subject { get; init; }

    /// <summary>The upstream token's scope.</summary>
    public string? Scope { get; init; }

    /// <summary>The <c>mission.approver</c> of the upstream token, or
    /// <see langword="null"/> when the upstream token carries no mission. A
    /// present approver means the chain is anchored to a PS for governance.</summary>
    public string? MissionApprover { get; init; }
    public MissionClaim? Mission { get; init; }
    public TokenVerifier.VerifiedToken? Verified { get; init; }
    public string? Account => Verified?.Account;
}

/// <summary>
/// Validates an <c>upstream_token</c> per §Upstream Token Verification.
/// Used by PS implementations to validate tokens from intermediary resources
/// before issuing downstream auth tokens.
/// </summary>
public sealed class UpstreamTokenValidator
{
    private readonly MetadataClient _metadata;
    private readonly JwksClient _jwks;
    private readonly TokenVerifier _verifier;

    public UpstreamTokenValidator(MetadataClient metadata, JwksClient jwks, TokenVerifier? verifier = null)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        _verifier = verifier ?? new TokenVerifier { EgressPolicy = metadata.Policy };
    }

    /// <summary>
    /// Validates an upstream_token per §Upstream Token Verification steps 1–4.
    /// </summary>
    /// <param name="upstreamToken">The compact JWS auth token to validate.</param>
    /// <param name="expectedAudience">The intermediary resource's own URL (must match <c>aud</c>).</param>
    /// <param name="trustedIssuers">Set of trusted AS/PS issuer URLs.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Validation result with parsed claims or error.</returns>
    public Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string expectedAudience,
        IReadOnlySet<string> trustedIssuers,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        return ValidateAsync(upstreamToken, expectedAudience, trustedIssuers.Contains, ct);
    }

    /// <summary>
    /// Validates an upstream_token per §Upstream Token Verification, deciding issuer
    /// trust (step 2) with a predicate rather than a static set.
    /// <paramref name="isTrustedIssuer"/> MUST return true only for an issuer the
    /// recipient previously brokered or is authorized to extend (e.g. self, or an
    /// Access Server it federates with).
    /// </summary>
    public async Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string expectedAudience,
        Func<string, bool> isTrustedIssuer,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamToken);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentNullException.ThrowIfNull(isTrustedIssuer);

        // Step 1: Standard auth token verification (signature, temporal, structure).
        // We don't enforce PoP binding (cnf.jwk vs HTTP signature key) since the
        // intermediary has already verified that. We only need structural + issuer verification.
        TokenVerifier.VerifiedToken verified;
        try
        {
            verified = await VerifyWithoutPoPAsync(upstreamToken, expectedAudience, ct);
            var originalKey = SignatureKeyParser.Confirmation(verified.Payload);
            var originalAgent = (string?)verified.Payload["agent"];
            if (!AgentId.TryParse(originalAgent, out _, out _, _verifier.EgressPolicy))
                throw new TokenVerificationException("invalid_upstream_token: missing or invalid 'agent'.");
            verified = await _verifier.VerifyAuthTokenWithJwksAsync(upstreamToken, _metadata, _jwks,
                expectedAudience, originalKey, originalAgent!, cancellationToken: ct);
        }
        catch (Exception ex) when (ex is TokenVerificationException or AAuthVerificationException or FormatException or ArgumentException or InvalidOperationException)
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = ex.Message,
                FailureCode = ex is TokenVerificationException token ? token.Code
                    : ex is AAuthVerificationException signature ? signature.Code : AAuth.Errors.SignatureErrorCode.InvalidJwt,
            };
        }

        // Step 2: Verify iss is a trusted issuer.
        if (!isTrustedIssuer(verified.Issuer))
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = $"untrusted_issuer: '{verified.Issuer}' is not in the trusted issuers set.",
            };
        }

        // Step 3: aud already verified by Verify() above.

        // Step 4: Extract act for the caller to nest. `act` is OPTIONAL in draft-08
        // — absent when the upstream token was a direct authorization (no chaining).
        var act = verified.Payload["act"] as JsonObject;
        var agent = (string?)verified.Payload["agent"];

        // §Upstream Token Verification step 1 requires full Auth Token Verification.
        // VerifyWithoutPoPAsync covers JWT trust; enforce the request-context presence
        // checks the upstream token must still satisfy: `agent` (used to compose the
        // downstream act node — a null here would otherwise throw at BuildNestedAct)
        // and a `dwk` constrained to the auth-token set (the four-party mission gate
        // classifies AS vs PS from `dwk`, so an out-of-set value MUST NOT pass).
        if (string.IsNullOrEmpty(agent))
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = "invalid_upstream_token: missing 'agent'.",
            };
        }
        var upstreamDwk = (string?)verified.Payload["dwk"];
        if (upstreamDwk != AuthTokenBuilder.PersonDwk && upstreamDwk != AuthTokenBuilder.AccessDwk)
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = $"invalid_upstream_token: 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}'.",
            };
        }

        // When present, validate chain well-formedness: each level has `agent`,
        // depth is within limits. The presenter is the top-level `agent`; `act.agent`
        // identifies the upstream delegator and is intentionally different — so there
        // is no self-reference check.
        if (act is not null && !ActChainBuilder.ValidateChain(act, _verifier.MaxActDepth, _verifier.EgressPolicy))
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = "invalid_act_chain: act chain is malformed (missing agent or exceeds max depth).",
            };
        }

        // Return the upstream token's agent and its (optional) act chain. The caller
        // composes the downstream act via ActChainBuilder.BuildNestedAct(agent, act)
        // per §Upstream Token Verification step 4.
        return new UpstreamTokenValidationResult
        {
            IsValid = true,
            ExpiresAt = verified.ExpiresAt,
            UpstreamAct = act?.DeepClone() as JsonObject,
            Issuer = verified.Issuer,
            IssuerDwk = upstreamDwk,
            Agent = agent,
            Subject = (string?)verified.Payload["sub"],
            Scope = (string?)verified.Payload["scope"],
            MissionApprover = (string?)(verified.Payload["mission"] as JsonObject)?["approver"],
            Mission = MissionClaim.FromPayload(verified.Payload, _metadata.Policy),
            Verified = verified,
        };
    }

    private async Task<TokenVerifier.VerifiedToken> VerifyWithoutPoPAsync(
        string jwt, string expectedAudience, CancellationToken ct)
    {
        // Decode to find issuer and dwk for key resolution.
        var (_, payload) = _verifier.ReadStructure(jwt, AuthTokenBuilder.TokenType);
        var dwk = (string?)payload["dwk"]
            ?? throw new TokenVerificationException("Token is missing 'dwk'.");
        return await _verifier.VerifyWithJwksAsync(jwt, _metadata, _jwks,
            AuthTokenBuilder.TokenType, dwk, expectedAudience, ct).ConfigureAwait(false);
    }
}
