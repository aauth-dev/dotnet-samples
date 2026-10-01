using System;
using System.Text.Json.Nodes;
using AAuth.Errors;

namespace AAuth.Crypto;

/// <summary>
/// Factory for creating <see cref="IAAuthKey"/> instances from JWK JSON
/// objects by dispatching on <c>kty</c>/<c>crv</c>.
/// </summary>
public static class KeyFactory
{
    /// <summary>
    /// Create a local key from a JWK JSON object. The key can sign and export
    /// when the JWK carries <c>d</c>.
    /// </summary>
    /// <param name="jwk">The JWK as a JSON object.</param>
    /// <returns>An <see cref="IAAuthExportableKey"/> of the appropriate concrete type.</returns>
    /// <exception cref="ArgumentException">If the key type/curve is unsupported or malformed.</exception>
    public static IAAuthExportableKey FromJwk(JsonObject jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        var algorithm = Validate(jwk);
        try
        {
            return algorithm == AAuthKey.Ed25519Algorithm
                ? AAuthKey.FromJwk(jwk) : EcdsaAAuthKey.FromJwk(jwk);
        }
        catch (JwkValidationException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException)
        {
            throw new JwkValidationException(SignatureErrorCode.InvalidKey, "Malformed JWK key material.", exception);
        }
    }

    public static IAAuthKey FromPublicJwk(JsonObject jwk)
    {
        Validate(jwk);
        if (new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" }.Any(jwk.ContainsKey))
            throw new JwkValidationException(SignatureErrorCode.InvalidKey, "Wire JWK must contain public key material only.");
        return FromJwk(jwk);
    }

    internal static string Validate(JsonObject jwk)
    {
        var algorithm = ReadString(jwk, "alg", required: false);
        if (algorithm is not (AAuthKey.Ed25519Algorithm or EcdsaAAuthKey.Alg))
            throw new JwkValidationException(SignatureErrorCode.UnsupportedAlgorithm, "JWK requires a supported fully specified asymmetric alg.");
        var keyType = ReadString(jwk, "kty");
        var curve = ReadString(jwk, "crv");
        if (algorithm == AAuthKey.Ed25519Algorithm && (keyType != AAuthKey.KeyType || curve != AAuthKey.Curve)
            || algorithm == EcdsaAAuthKey.Alg && (keyType != EcdsaAAuthKey.Kty || curve != EcdsaAAuthKey.CurveName))
            throw new JwkValidationException(SignatureErrorCode.InvalidKey, "JWK alg disagrees with kty or crv.");
        return algorithm;
    }

    internal static string? ReadString(JsonObject jwk, string name, bool required = true)
    {
        if (!jwk.ContainsKey(name) && !required) return null;
        if (jwk[name] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrEmpty(text))
            return text;
        throw new JwkValidationException(SignatureErrorCode.InvalidKey, $"JWK '{name}' must be a nonempty string.");
    }

    internal static byte[] ReadCoordinate(JsonObject jwk, string name)
    {
        var text = ReadString(jwk, name)!;
        try
        {
            var bytes = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(text);
            if (bytes.Length != 32 || Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(bytes) != text)
                throw new FormatException();
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new JwkValidationException(SignatureErrorCode.InvalidKey, $"Invalid JWK '{name}' coordinate.", exception);
        }
    }

    /// <summary>
    /// Try to create an <see cref="IAAuthKey"/> from a JWK JSON object.
    /// Returns null if the key type is unsupported or the JWK is malformed.
    /// </summary>
    public static IAAuthKey? TryFromJwk(JsonObject jwk)
    {
        if (jwk is null) return null;

        try
        {
            return FromPublicJwk(jwk);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
