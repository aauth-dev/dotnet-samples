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
        AAuthKey ConfirmationKey);

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
