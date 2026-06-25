using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Tokens;

/// <summary>
/// Result of upstream token validation.
/// </summary>
public sealed record UpstreamTokenValidationResult
{
    /// <summary>Whether the upstream token is valid.</summary>
    public bool IsValid { get; init; }

    /// <summary>Error description when invalid.</summary>
    public string? Error { get; init; }

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
        _verifier = verifier ?? new TokenVerifier();
    }

    /// <summary>
    /// Validates an upstream_token per §Upstream Token Verification steps 1–4.
    /// </summary>
    /// <param name="upstreamToken">The compact JWS auth token to validate.</param>
    /// <param name="expectedAudience">The intermediary resource's own URL (must match <c>aud</c>).</param>
    /// <param name="trustedIssuers">Set of trusted AS/PS issuer URLs.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Validation result with parsed claims or error.</returns>
    public async Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string expectedAudience,
        IReadOnlySet<string> trustedIssuers,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamToken);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentNullException.ThrowIfNull(trustedIssuers);

        // Step 1: Standard auth token verification (signature, temporal, structure).
        // We don't enforce PoP binding (cnf.jwk vs HTTP signature key) since the
        // intermediary has already verified that. We only need structural + issuer verification.
        TokenVerifier.VerifiedToken verified;
        try
        {
            verified = await VerifyWithoutPoPAsync(upstreamToken, expectedAudience, ct);
        }
        catch (TokenVerificationException ex)
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = ex.Message,
            };
        }

        // Step 2: Verify iss is a trusted issuer.
        if (!trustedIssuers.Contains(verified.Issuer))
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
        if (act is not null && !ActChainBuilder.ValidateChain(act, _verifier.MaxActDepth))
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
            UpstreamAct = act?.DeepClone() as JsonObject,
            Issuer = verified.Issuer,
            IssuerDwk = upstreamDwk,
            Agent = agent,
            Subject = (string?)verified.Payload["sub"],
            Scope = (string?)verified.Payload["scope"],
            MissionApprover = (string?)(verified.Payload["mission"] as JsonObject)?["approver"],
        };
    }

    private async Task<TokenVerifier.VerifiedToken> VerifyWithoutPoPAsync(
        string jwt, string expectedAudience, CancellationToken ct)
    {
        // Decode to find issuer and dwk for key resolution.
        var segments = jwt.Split('.');
        if (segments.Length != 3)
            throw new TokenVerificationException("JWT is not a compact JWS.");

        var payload = TokenVerifier.DecodeJsonSegment(segments[1], "payload");
        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        var dwk = (string?)payload["dwk"]
            ?? throw new TokenVerificationException("Token is missing 'dwk'.");

        // Resolve issuer's signing key.
        var metaUrl = MetadataClient.BuildUrl(iss, dwk);
        var meta = await _metadata.FetchAsync(metaUrl, ct);
        var jwksUriStr = (string?)meta["jwks_uri"]
            ?? throw new TokenVerificationException($"Issuer metadata missing 'jwks_uri'.");

        var header = TokenVerifier.DecodeJsonSegment(segments[0], "header");
        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");
        var issuerKey = await _jwks.ResolveKeyAsync(new Uri(jwksUriStr), kid, ct)
            ?? throw new TokenVerificationException($"Could not resolve signing key '{kid}' from '{jwksUriStr}'.");

        // Basic verification (signature, temporal, audience) without PoP enforcement.
        return _verifier.Verify(jwt, issuerKey, AuthTokenBuilder.TokenType, dwk, expectedAudience);
    }
}
