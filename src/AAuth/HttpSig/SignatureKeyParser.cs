using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Errors;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

public static class SignatureKeyParser
{
    public sealed record ParsedSignatureKey(string Jwt, JsonObject Header, JsonObject Payload, IAAuthKey ConfirmationKey)
    {
        public string? TokenId => Text(Payload, "jti");
        public DateTimeOffset? Expiration => Payload["exp"] is JsonValue value && value.TryGetValue<long>(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
    }

    public sealed class ParsedSignatureKeyInfo
    {
        public required string Scheme { get; init; }
        public string Label { get; init; } = "sig";
        public IAAuthKey? ConfirmationKey { get; init; }
        public string? Jkt { get; init; }
        public string? Identifier { get; init; }
        public string? Dwk { get; init; }
        public string? JwksUri { get; init; }
        public string? Kid { get; init; }
        public string? Jwt { get; init; }
        public JsonObject? Header { get; init; }
        public JsonObject? Payload { get; init; }
    }

    public static ParsedSignatureKeyInfo ParseAny(string signatureKeyHeader, string label = "sig")
    {
        var (scheme, parameters) = SignatureKeyHeader.Parse(signatureKeyHeader, label);
        switch (scheme)
        {
            case "hwk":
                if (new[] { "kid", "jwk", "jkt", "d", "k", "p", "q", "dp", "dq", "qi", "oth" }.Any(parameters.ContainsKey))
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Prohibited hwk parameter.");
                var jwk = new JsonObject();
                foreach (var name in new[] { "kty", "crv", "x", "y", "n", "e", "alg" })
                    if (parameters.ContainsKey(name)) jwk[name] = StructuredFields.RequiredString(parameters, name);
                var key = PublicKey(jwk);
                return new() { Scheme = scheme, Label = label, ConfirmationKey = key, Jkt = key.ComputeJwkThumbprint() };
            case "jwks_uri":
                if (parameters.ContainsKey("uri"))
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, "Obsolete jwks_uri carrier.");
                return new()
                {
                    Scheme = scheme, Label = label,
                    Identifier = StructuredFields.RequiredString(parameters, "id"),
                    Dwk = StructuredFields.RequiredString(parameters, "dwk"),
                    Kid = StructuredFields.RequiredString(parameters, "kid"),
                };
            case "jwks":
                return new()
                {
                    Scheme = scheme, Label = label,
                    Identifier = StructuredFields.RequiredString(parameters, "url"),
                    JwksUri = StructuredFields.RequiredString(parameters, "url"),
                    Kid = StructuredFields.RequiredString(parameters, "kid"),
                };
            case "jwt":
            case "self-jwt":
            case "jkt-jwt":
                if (parameters.ContainsKey("jkt") || scheme == "self-jwt" && parameters.ContainsKey("cache"))
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Prohibited assertion parameter.");
                if (parameters.TryGetValue("cache", out var cache) && cache is not bool)
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "cache must be Boolean.");
                var jwt = StructuredFields.RequiredString(parameters, "jwt");
                var segments = jwt.Split('.');
                if (segments.Length != 3 || segments.Any(string.IsNullOrEmpty))
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT is not a compact JWS.");
                var header = DecodeJsonSegment(segments[0]);
                var payload = DecodeJsonSegment(segments[1]);
                if (scheme == "self-jwt" && payload.ContainsKey("cnf"))
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "self-jwt MUST NOT contain cnf.");
                if (scheme != "self-jwt" && payload["cnf"] is not JsonObject)
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires cnf.jwk.");
                if (parameters.TryGetValue("cache", out cache) && cache is true && Text(payload, "jti") is null)
                    throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Cacheable assertion requires jti.");
                return new() { Scheme = scheme, Label = label, Jwt = jwt, Header = header, Payload = payload };
            default:
                throw new AAuthVerificationException(SignatureErrorCode.UnsupportedScheme, $"Unsupported Signature-Key scheme '{scheme}'.");
        }
    }

    public static ParsedSignatureKey Parse(string signatureKeyHeader, string label = "sig")
    {
        var info = ParseAny(signatureKeyHeader, label);
        if (info.Scheme != "jwt")
            throw new AAuthVerificationException(SignatureErrorCode.UnsupportedScheme, "Expected jwt carrier.");
        return new(info.Jwt!, info.Header!, info.Payload!, Confirmation(info.Payload!));
    }

    internal static IAAuthKey Confirmation(JsonObject payload)
    {
        if (payload["cnf"] is not JsonObject confirmation || confirmation["jwk"] is not JsonObject jwk)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires cnf.jwk.");
        return PublicKey(jwk);
    }

    internal static IAAuthKey PublicKey(JsonObject jwk)
    {
        try { return KeyFactory.FromPublicJwk(jwk); }
        catch (JwkValidationException exception)
        { throw new AAuthVerificationException(exception.Code, exception.Message, exception); }
    }

    internal static string? Text(JsonObject? document, string name) =>
        document?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static JsonObject DecodeJsonSegment(string segment)
    {
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(segment);
            if (Base64UrlEncoder.Encode(bytes) != segment) throw new FormatException();
            return JsonNode.Parse(bytes) as JsonObject ?? throw new JsonException();
        }
        catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException)
        { throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Invalid JWT JSON segment.", exception); }
    }
}
