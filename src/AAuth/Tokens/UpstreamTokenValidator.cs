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

    /// <summary>The <c>act</c> object ready for nesting into the downstream token.
    /// When <c>intermediaryAgentId</c> was provided to <see cref="UpstreamTokenValidator.ValidateAsync"/>,
    /// this is the fully constructed nested act (intermediary wrapping upstream).
    /// Otherwise, this is the raw upstream act for the caller to nest manually.</summary>
    public JsonObject? UpstreamAct { get; init; }

    /// <summary>The upstream token's issuer.</summary>
    public string? Issuer { get; init; }

    /// <summary>The upstream token's agent identifier.</summary>
    public string? Agent { get; init; }

    /// <summary>The upstream token's subject.</summary>
    public string? Subject { get; init; }

    /// <summary>The upstream token's scope.</summary>
    public string? Scope { get; init; }
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
    /// <param name="intermediaryAgentId">
    /// The agent identity of the intermediary resource presenting the upstream token.
    /// When provided, used to construct the nested act claim (step 4).
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Validation result with parsed claims or error.</returns>
    public async Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string expectedAudience,
        IReadOnlySet<string> trustedIssuers,
        string? intermediaryAgentId = null,
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

        // Step 4: Extract act for caller to nest.
        var act = verified.Payload["act"] as JsonObject;
        if (act is null)
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = "missing_act: upstream token is missing required 'act' claim.",
            };
        }

        // Validate chain well-formedness: each level has 'sub', depth is within limits.
        if (!ActChainBuilder.ValidateChain(act, _verifier.MaxActDepth))
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = "invalid_act_chain: act chain is malformed (missing sub or exceeds max depth).",
            };
        }

        // Verify act.sub matches the 'agent' claim (the token was issued for this agent).
        var actSub = (string?)act["sub"];
        var agent = (string?)verified.Payload["agent"];
        if (actSub != agent)
        {
            return new UpstreamTokenValidationResult
            {
                IsValid = false,
                Error = $"act_sub_mismatch: act.sub '{actSub}' does not match agent '{agent}'.",
            };
        }

        // Build the nested act for the downstream token if intermediaryAgentId provided (step 4).
        JsonObject? nestedAct = intermediaryAgentId is not null
            ? ActChainBuilder.BuildNestedAct(intermediaryAgentId, act)
            : act.DeepClone() as JsonObject;

        return new UpstreamTokenValidationResult
        {
            IsValid = true,
            UpstreamAct = nestedAct,
            Issuer = verified.Issuer,
            Agent = agent,
            Subject = (string?)verified.Payload["sub"],
            Scope = (string?)verified.Payload["scope"],
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
