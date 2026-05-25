using System;
using System.Text.Json.Nodes;

namespace AAuth.Crypto;

/// <summary>
/// Factory for creating <see cref="IAAuthKey"/> instances from JWK JSON
/// objects by dispatching on <c>kty</c>/<c>crv</c>.
/// </summary>
public static class KeyFactory
{
    /// <summary>
    /// Create an <see cref="IAAuthKey"/> from a JWK JSON object.
    /// </summary>
    /// <param name="jwk">The JWK as a JSON object.</param>
    /// <returns>An <see cref="IAAuthKey"/> of the appropriate concrete type.</returns>
    /// <exception cref="ArgumentException">If the key type/curve is unsupported or malformed.</exception>
    public static IAAuthKey FromJwk(JsonObject jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        var kty = (string?)jwk["kty"];
        var crv = (string?)jwk["crv"];

        return (kty, crv) switch
        {
            (AAuthKey.KeyType, AAuthKey.Curve) => AAuthKey.FromJwk(jwk),       // OKP / Ed25519
            (EcdsaAAuthKey.Kty, EcdsaAAuthKey.CurveName) => EcdsaAAuthKey.FromJwk(jwk), // EC / P-256
            _ => throw new ArgumentException(
                $"Unsupported key type: kty='{kty}', crv='{crv}'. " +
                $"Supported: OKP/Ed25519, EC/P-256.", nameof(jwk)),
        };
    }

    /// <summary>
    /// Try to create an <see cref="IAAuthKey"/> from a JWK JSON object.
    /// Returns null if the key type is unsupported or the JWK is malformed.
    /// </summary>
    public static IAAuthKey? TryFromJwk(JsonObject jwk)
    {
        if (jwk is null) return null;

        var kty = (string?)jwk["kty"];
        var crv = (string?)jwk["crv"];

        try
        {
            return (kty, crv) switch
            {
                (AAuthKey.KeyType, AAuthKey.Curve) => AAuthKey.FromJwk(jwk),
                (EcdsaAAuthKey.Kty, EcdsaAAuthKey.CurveName) => EcdsaAAuthKey.FromJwk(jwk),
                _ => null,
            };
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
