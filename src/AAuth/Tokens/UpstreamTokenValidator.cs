using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.HttpSig;

namespace AAuth.Tokens;

/// <summary>
/// Result of upstream token validation (§Upstream Token Verification).
/// </summary>
public sealed record UpstreamTokenValidationResult
{
    /// <summary>Whether the upstream token is valid.</summary>
    public bool IsValid { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Error description when invalid.</summary>
    public string? Error { get; init; }
    public AAuth.Errors.SignatureErrorCode FailureCode { get; init; } = AAuth.Errors.SignatureErrorCode.InvalidJwt;

    /// <summary>The upstream token's issuer.</summary>
    public string? Issuer { get; init; }

    /// <summary>The upstream token's <c>typ</c>: <c>aa-person+jwt</c> or <c>aa-auth+jwt</c>.</summary>
    public string? TokenType { get; init; }

    /// <summary>
    /// The person server the upstream token names: a person token's <c>iss</c>,
    /// an auth token's <c>ps</c>. Downstream token requests route here.
    /// </summary>
    public string? PersonServer { get; init; }

    /// <summary>The intermediary the upstream token was presented to (its <c>aud</c>).</summary>
    public string? Audience { get; init; }

    /// <summary>The directed subject at the intermediary. MUST NOT be copied downstream.</summary>
    public string? Subject { get; init; }

    /// <summary>The upstream auth token's scope; <see langword="null"/> for a person token.</summary>
    public string? Scope { get; init; }

    /// <summary>The mission the chain runs under, if any.</summary>
    public string? MissionS256 { get; init; }
    public string? Tenant { get; init; }
    public TokenVerifier.VerifiedToken? Verified { get; init; }
    public string? Account => Verified?.Account;
}

/// <summary>
/// Validates an <c>upstream_token</c> (a person token or auth token) per
/// §Upstream Token Verification. Used by PS and AS token endpoints to verify
/// the token a calling agent presented to an intermediary.
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
    /// Validates an upstream token per §Upstream Token Verification steps 1–3.
    /// </summary>
    /// <param name="upstreamToken">The compact JWS person or auth token.</param>
    /// <param name="intermediary">
    /// The <c>iss</c> of the intermediary's agent token; the upstream <c>aud</c> MUST equal it.
    /// </param>
    /// <param name="expectedPersonServer">
    /// The PS a person token's <c>iss</c> / auth token's <c>ps</c> MUST name: this PS
    /// at a PS, the signing PS at an AS.
    /// </param>
    /// <param name="isTrustedAuthTokenIssuer">
    /// At a PS: accepts an auth token's <c>iss</c> only when it is this PS or an AS
    /// this PS federated with. At an AS, pass <c>_ =&gt; true</c>.
    /// </param>
    public async Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string intermediary,
        string expectedPersonServer,
        Func<string, bool> isTrustedAuthTokenIssuer,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamToken);
        ArgumentException.ThrowIfNullOrEmpty(intermediary);
        ArgumentException.ThrowIfNullOrEmpty(expectedPersonServer);
        ArgumentNullException.ThrowIfNull(isTrustedAuthTokenIssuer);

        TokenVerifier.VerifiedToken verified;
        string typ;
        try
        {
            var parts = upstreamToken.Split('.');
            if (parts.Length != 3) throw new TokenVerificationException("upstream_token is not a compact JWS.");
            typ = (string?)TokenVerifier.DecodeJsonSegment(parts[0], "header")["typ"]
                ?? throw new TokenVerificationException("upstream_token is missing typ.");
            // cnf is the calling agent's key and is not compared with the key that
            // signed this request (the intermediary's); bind to the token's own cnf.
            var callingAgentKey = SignatureKeyParser.Confirmation(TokenVerifier.DecodeJsonSegment(parts[1], "payload"));
            verified = typ switch
            {
                PersonTokenBuilder.TokenType => await _verifier.VerifyPersonTokenWithJwksAsync(
                    upstreamToken, _metadata, _jwks, intermediary, callingAgentKey, ct),
                AuthTokenBuilder.TokenType => await _verifier.VerifyAuthTokenWithJwksAsync(
                    upstreamToken, _metadata, _jwks, intermediary, callingAgentKey, cancellationToken: ct),
                _ => throw new TokenVerificationException("upstream_token must be a person token or an auth token."),
            };
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

        var personServer = typ == PersonTokenBuilder.TokenType ? verified.Issuer : (string?)verified.Payload["ps"];
        if (!string.Equals(personServer, expectedPersonServer, StringComparison.Ordinal))
            return Invalid($"upstream_token names person server '{personServer}', expected '{expectedPersonServer}'.");
        if (typ == AuthTokenBuilder.TokenType
            && !string.Equals(verified.Issuer, expectedPersonServer, StringComparison.Ordinal)
            && !isTrustedAuthTokenIssuer(verified.Issuer))
            return Invalid($"upstream auth token issuer '{verified.Issuer}' is not trusted.");

        return new UpstreamTokenValidationResult
        {
            IsValid = true,
            ExpiresAt = verified.ExpiresAt,
            Issuer = verified.Issuer,
            TokenType = typ,
            PersonServer = personServer,
            Audience = intermediary,
            Subject = verified.Subject,
            Scope = (string?)verified.Payload["scope"],
            MissionS256 = verified.MissionS256,
            Tenant = verified.Tenant,
            Verified = verified,
        };
    }

    private static UpstreamTokenValidationResult Invalid(string error) => new() { IsValid = false, Error = error };
}
