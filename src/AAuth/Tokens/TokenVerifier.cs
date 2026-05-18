using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Verifies AAuth JWTs (<c>aa-agent+jwt</c>, <c>aa-resource+jwt</c>,
/// <c>aa-auth+jwt</c>): structural checks, signature verification, and the
/// standard temporal / audience / binding claims.
/// </summary>
/// <remarks>
/// Verification is hand-rolled with BouncyCastle to mirror the issuer-side
/// signing path; see the plan's "Implementation Decisions" for the
/// trade-off. Out of scope here: actor-chain (<c>act</c>) walking, mission
/// validation, R3.
/// </remarks>
public sealed class TokenVerifier
{
    /// <summary>Clock injection point.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>Tolerance applied to <c>exp</c>/<c>iat</c> checks.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Parsed claims from a verified token.</summary>
    public sealed record VerifiedToken(
        JsonObject Header,
        JsonObject Payload,
        string Issuer,
        string TokenType);

    /// <summary>
    /// Verify a token whose issuer's public key has already been resolved
    /// (e.g. an <c>aa-agent+jwt</c> in self-issued mode where the issuer
    /// signs with the same key bound in <c>cnf.jwk</c>, or any token whose
    /// JWKS has been fetched).
    /// </summary>
    /// <param name="jwt">Compact JWT.</param>
    /// <param name="issuerKey">Public key expected to have signed the JWT.</param>
    /// <param name="expectedType">Required <c>typ</c> header value.</param>
    /// <param name="expectedDwk">Required <c>dwk</c> claim value.</param>
    /// <param name="expectedAudience">If non-null, the required <c>aud</c> claim value.</param>
    public VerifiedToken Verify(
        string jwt,
        AAuthKey issuerKey,
        string expectedType,
        string expectedDwk,
        string? expectedAudience = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(issuerKey);
        ArgumentException.ThrowIfNullOrEmpty(expectedType);
        ArgumentException.ThrowIfNullOrEmpty(expectedDwk);

        var segments = jwt.Split('.');
        if (segments.Length != 3)
        {
            throw new TokenVerificationException("JWT is not a compact JWS.");
        }

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        // RFC 7515 — refuse `alg: none` and require EdDSA (the only algorithm
        // AAuth supports today; ES256 lands when the signer does).
        var alg = (string?)header["alg"];
        if (alg != AAuthKey.Algorithm)
        {
            throw new TokenVerificationException(
                $"Unsupported or missing 'alg' (expected '{AAuthKey.Algorithm}', got '{alg}').");
        }

        var typ = (string?)header["typ"];
        if (typ != expectedType)
        {
            throw new TokenVerificationException(
                $"Unexpected 'typ' (expected '{expectedType}', got '{typ}').");
        }

        var dwk = (string?)payload["dwk"];
        if (dwk != expectedDwk)
        {
            throw new TokenVerificationException(
                $"Unexpected 'dwk' (expected '{expectedDwk}', got '{dwk}').");
        }

        byte[] signature;
        try
        {
            signature = Base64UrlEncoder.DecodeBytes(segments[2]);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException("JWT signature is not valid base64url.", ex);
        }

        var signingInput = segments[0] + "." + segments[1];
        if (!issuerKey.Verify(Encoding.ASCII.GetBytes(signingInput), signature))
        {
            throw new TokenVerificationException("JWT signature verification failed.");
        }

        // Temporal claims.
        var now = Clock();
        var nowUnix = now.ToUnixTimeSeconds();
        var skew = (long)ClockSkew.TotalSeconds;

        if (TryGetUnixTime(payload, "exp", out var exp))
        {
            if (exp + skew < nowUnix)
            {
                throw new TokenVerificationException($"Token expired at {exp} (now={nowUnix}).");
            }
        }
        else
        {
            throw new TokenVerificationException("Token is missing 'exp'.");
        }

        if (TryGetUnixTime(payload, "iat", out var iat))
        {
            if (iat - skew > nowUnix)
            {
                throw new TokenVerificationException($"Token 'iat'={iat} is in the future (now={nowUnix}).");
            }
        }

        // Audience binding (when the caller cares).
        if (expectedAudience is not null)
        {
            var aud = (string?)payload["aud"];
            if (aud != expectedAudience)
            {
                throw new TokenVerificationException(
                    $"Token 'aud' does not match expected audience (expected '{expectedAudience}', got '{aud}').");
            }
        }

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!Uri.TryCreate(iss, UriKind.Absolute, out var issUri) || issUri.Scheme != "https")
        {
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL.");
        }

        return new VerifiedToken(header, payload, iss, typ);
    }

    /// <summary>
    /// Verify a self-issued agent token where the issuer's public key equals
    /// the <c>cnf.jwk</c> bound in the token's payload. This is the simple
    /// demo mode used by the AgentConsole sample where the agent acts as its
    /// own AP. Production deployments fetch the AP's JWKS instead.
    /// </summary>
    public VerifiedToken VerifySelfIssuedAgentToken(string jwt, AAuthKey confirmationKey) =>
        Verify(
            jwt,
            confirmationKey,
            AgentTokenBuilder.TokenType,
            AgentTokenBuilder.AgentDwk);

    /// <summary>
    /// Resolve the issuer's signing key via well-known metadata + JWKS, then
    /// verify the token. Used by resource servers verifying inbound auth
    /// tokens and by Person Servers verifying resource tokens.
    /// </summary>
    public async Task<VerifiedToken> VerifyWithJwksAsync(
        string jwt,
        MetadataClient metadata,
        JwksClient jwks,
        string expectedType,
        string expectedDwk,
        string? expectedAudience,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        var segments = jwt.Split('.');
        if (segments.Length != 3)
        {
            throw new TokenVerificationException("JWT is not a compact JWS.");
        }

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        var metadataUrl = MetadataClient.BuildUrl(iss, expectedDwk);
        JsonObject metadataDoc;
        try
        {
            metadataDoc = await metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"Failed to fetch issuer metadata from {metadataUrl}.", ex);
        }

        var jwksUriRaw = (string?)metadataDoc["jwks_uri"]
            ?? throw new TokenVerificationException($"Issuer metadata at {metadataUrl} is missing 'jwks_uri'.");
        if (!Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
        {
            throw new TokenVerificationException($"Issuer metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        }

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        return Verify(jwt, issuerKey, expectedType, expectedDwk, expectedAudience);
    }

    private static bool TryGetUnixTime(JsonObject payload, string claim, out long value)
    {
        value = 0;
        if (payload[claim] is JsonValue v && v.TryGetValue<long>(out var l))
        {
            value = l;
            return true;
        }
        return false;
    }

    private static JsonObject DecodeJsonSegment(string segment, string label)
    {
        byte[] bytes;
        try
        {
            bytes = Base64UrlEncoder.DecodeBytes(segment);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"JWT {label} is not valid base64url.", ex);
        }

        try
        {
            return JsonNode.Parse(bytes) as JsonObject
                ?? throw new TokenVerificationException($"JWT {label} is not a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new TokenVerificationException($"JWT {label} is not valid JSON.", ex);
        }
    }
}

/// <summary>Thrown when AAuth JWT verification fails for any reason.</summary>
public sealed class TokenVerificationException : Exception
{
    /// <summary>Create an exception with a message.</summary>
    public TokenVerificationException(string message) : base(message) { }

    /// <summary>Create an exception with a message and inner exception.</summary>
    public TokenVerificationException(string message, Exception inner) : base(message, inner) { }
}
