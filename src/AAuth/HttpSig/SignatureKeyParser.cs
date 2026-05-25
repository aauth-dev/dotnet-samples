using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

/// <summary>
/// Extracts the carrier token from a <c>Signature-Key</c> header and the
/// agent's confirmation key (<c>cnf.jwk</c>) from inside that token. Used by
/// the AAuth verification middleware to obtain the public key for RFC 9421
/// signature verification before any external trust check.
/// </summary>
/// <remarks>
/// Only the <c>sig=jwt</c> scheme is supported. The token's signature is
/// <em>not</em> validated here — that is a separate step performed by
/// <see cref="Tokens.TokenVerifier"/> against the issuer's JWKS. This parser
/// only does the structural decoding required to obtain a public key to
/// verify the HTTP signature.
/// </remarks>
public static class SignatureKeyParser
{
    /// <summary>Result of parsing a Signature-Key header carrying a JWT.</summary>
    /// <param name="Jwt">The raw JWT compact serialization.</param>
    /// <param name="Header">Decoded JOSE header.</param>
    /// <param name="Payload">Decoded JWT payload.</param>
    /// <param name="ConfirmationKey">The <c>cnf.jwk</c> key — what signed the HTTP request.</param>
    public sealed record ParsedSignatureKey(
        string Jwt,
        JsonObject Header,
        JsonObject Payload,
        AAuthKey ConfirmationKey)
    {
        /// <summary>Token identifier (<c>jti</c>) if present.</summary>
        public string? TokenId => Payload["jti"]?.GetValue<string>();

        /// <summary>Token expiration (<c>exp</c>) if present.</summary>
        public DateTimeOffset? Expiration
        {
            get
            {
                var exp = Payload["exp"];
                if (exp is null) return null;
                return DateTimeOffset.FromUnixTimeSeconds(exp.GetValue<long>());
            }
        }
    }

    /// <summary>
    /// Result of parsing a Signature-Key header with any scheme. For schemes
    /// where the key is not inline (hwk, jwks_uri), use the reference fields
    /// to resolve the key externally.
    /// </summary>
    public sealed class ParsedSignatureKeyInfo
    {
        /// <summary>The scheme name (jwt, hwk, jkt-jwt, jwks_uri).</summary>
        public required string Scheme { get; init; }

        /// <summary>The confirmation key (available for jwt and jkt-jwt schemes).</summary>
        public IAAuthKey? ConfirmationKey { get; init; }

        /// <summary>JWK thumbprint (available for hwk and jkt-jwt schemes).</summary>
        public string? Jkt { get; init; }

        /// <summary>JWKS URI (available for jwks_uri scheme).</summary>
        public string? JwksUri { get; init; }

        /// <summary>Key ID within a JWKS (available for jwks_uri scheme).</summary>
        public string? Kid { get; init; }

        /// <summary>Raw JWT (available for jwt and jkt-jwt schemes).</summary>
        public string? Jwt { get; init; }

        /// <summary>Decoded JWT header (available for jwt and jkt-jwt schemes).</summary>
        public JsonObject? Header { get; init; }

        /// <summary>Decoded JWT payload (available for jwt and jkt-jwt schemes).</summary>
        public JsonObject? Payload { get; init; }
    }

    /// <summary>
    /// Parse a <c>Signature-Key</c> header supporting all schemes: jwt, hwk,
    /// jkt-jwt, jwks_uri. For non-jwt schemes, the caller must resolve the
    /// key externally (e.g. from a JWKS endpoint or local key store).
    /// </summary>
    public static ParsedSignatureKeyInfo ParseAny(string signatureKeyHeader)
    {
        ArgumentException.ThrowIfNullOrEmpty(signatureKeyHeader);
        var (scheme, parameters) = SignatureKeyHeader.Parse(signatureKeyHeader);

        return scheme switch
        {
            "jwt" => ParseJwtScheme(parameters),
            "hwk" => ParseHwkScheme(parameters),
            "jkt-jwt" => ParseJktJwtScheme(parameters),
            "jwks_uri" => ParseJwksUriScheme(parameters),
            _ => throw new AAuthVerificationException($"Unsupported Signature-Key scheme: '{scheme}'."),
        };
    }

    private static ParsedSignatureKeyInfo ParseJwtScheme(IReadOnlyDictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("jwt", out var jwt) || string.IsNullOrEmpty(jwt))
            throw new AAuthVerificationException("Signature-Key jwt scheme missing 'jwt' parameter.");

        var segments = jwt.Split('.');
        if (segments.Length != 3)
            throw new AAuthVerificationException("JWT in Signature-Key is not a compact JWS.");

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        var cnf = payload["cnf"] as JsonObject
            ?? throw new AAuthVerificationException("Token is missing the 'cnf' claim.");
        var jwk = cnf["jwk"] as JsonObject
            ?? throw new AAuthVerificationException("Token 'cnf' claim does not contain 'jwk'.");

        AAuthKey key;
        try { key = AAuthKey.FromJwk(jwk); }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        { throw new AAuthVerificationException("cnf.jwk is not a valid Ed25519 OKP key.", ex); }

        return new ParsedSignatureKeyInfo
        {
            Scheme = "jwt",
            ConfirmationKey = key,
            Jwt = jwt,
            Header = header,
            Payload = payload,
        };
    }

    private static ParsedSignatureKeyInfo ParseHwkScheme(IReadOnlyDictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("jwk", out var jwkB64) || string.IsNullOrEmpty(jwkB64))
            throw new AAuthVerificationException("Signature-Key hwk scheme missing 'jwk' parameter.");

        IAAuthKey key;
        try
        {
            var jwkJson = System.Text.Encoding.UTF8.GetString(
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwkB64));
            var jwkObj = System.Text.Json.Nodes.JsonObject.Parse(jwkJson) as JsonObject
                ?? throw new AAuthVerificationException("Signature-Key hwk scheme: jwk is not a JSON object.");
            key = Crypto.KeyFactory.FromJwk(jwkObj);
        }
        catch (AAuthVerificationException) { throw; }
        catch (Exception ex)
        {
            throw new AAuthVerificationException($"Signature-Key hwk scheme: failed to parse inline jwk — {ex.Message}");
        }

        var jkt = parameters.TryGetValue("jkt", out var j) ? j : key.ComputeJwkThumbprint();

        return new ParsedSignatureKeyInfo
        {
            Scheme = "hwk",
            Jkt = jkt,
            ConfirmationKey = key,
        };
    }

    private static ParsedSignatureKeyInfo ParseJktJwtScheme(IReadOnlyDictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("jkt", out var jkt) || string.IsNullOrEmpty(jkt))
            throw new AAuthVerificationException("Signature-Key jkt-jwt scheme missing 'jkt' parameter.");
        if (!parameters.TryGetValue("jwt", out var jwt) || string.IsNullOrEmpty(jwt))
            throw new AAuthVerificationException("Signature-Key jkt-jwt scheme missing 'jwt' parameter.");

        var segments = jwt.Split('.');
        if (segments.Length != 3)
            throw new AAuthVerificationException("JWT in Signature-Key jkt-jwt is not a compact JWS.");

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        // Extract cnf.jwk if present (the key that matches the jkt)
        IAAuthKey? key = null;
        if (payload["cnf"] is JsonObject cnf && cnf["jwk"] is JsonObject jwk)
        {
            key = Crypto.KeyFactory.TryFromJwk(jwk);
        }

        return new ParsedSignatureKeyInfo
        {
            Scheme = "jkt-jwt",
            Jkt = jkt,
            ConfirmationKey = key,
            Jwt = jwt,
            Header = header,
            Payload = payload,
        };
    }

    private static ParsedSignatureKeyInfo ParseJwksUriScheme(IReadOnlyDictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("uri", out var uri) || string.IsNullOrEmpty(uri))
            throw new AAuthVerificationException("Signature-Key jwks_uri scheme missing 'uri' parameter.");
        if (!parameters.TryGetValue("kid", out var kid) || string.IsNullOrEmpty(kid))
            throw new AAuthVerificationException("Signature-Key jwks_uri scheme missing 'kid' parameter.");

        return new ParsedSignatureKeyInfo
        {
            Scheme = "jwks_uri",
            JwksUri = uri,
            Kid = kid,
        };
    }

    /// <summary>
    /// Parse a <c>Signature-Key</c> header value, decode the embedded JWT, and
    /// return the <c>cnf.jwk</c> public key for HTTP-signature verification.
    /// </summary>
    public static ParsedSignatureKey Parse(string signatureKeyHeader)
    {
        ArgumentException.ThrowIfNullOrEmpty(signatureKeyHeader);

        var jwt = SignatureKeyHeader.GetJwt(signatureKeyHeader)
            ?? throw new AAuthVerificationException(
                "Signature-Key scheme is not 'jwt' or is missing the jwt parameter.");

        var segments = jwt.Split('.');
        if (segments.Length != 3)
        {
            throw new AAuthVerificationException("JWT in Signature-Key is not a compact JWS.");
        }

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        var cnf = payload["cnf"] as JsonObject
            ?? throw new AAuthVerificationException("Token is missing the 'cnf' claim.");
        var jwk = cnf["jwk"] as JsonObject
            ?? throw new AAuthVerificationException("Token 'cnf' claim does not contain 'jwk'.");

        AAuthKey key;
        try
        {
            key = AAuthKey.FromJwk(jwk);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            throw new AAuthVerificationException("cnf.jwk is not a valid Ed25519 OKP key.", ex);
        }

        return new ParsedSignatureKey(jwt, header, payload, key);
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
            throw new AAuthVerificationException($"JWT {label} is not valid base64url.", ex);
        }

        try
        {
            return JsonNode.Parse(bytes) as JsonObject
                ?? throw new AAuthVerificationException($"JWT {label} is not a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new AAuthVerificationException($"JWT {label} is not valid JSON.", ex);
        }
    }
}
