using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Errors;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.HttpSig;

public static class NamingTokenVerifier
{
    public sealed record VerifiedNamingToken(IAAuthKey DurableKey, IAAuthKey ConfirmationKey, string Issuer, DateTimeOffset ExpiresAt);

    public static VerifiedNamingToken Verify(string jwt, DateTimeOffset now, TimeSpan clockSkew)
    {
        var info = SignatureKeyParser.ParseAny(SignatureKeyHeader.FormatJktJwt(jwt));
        var header = info.Header!;
        var payload = info.Payload!;
        if (SignatureKeyParser.Text(header, "typ") != AAuthConstants.TokenTypes.JktS256Jwt)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Unexpected naming JWT typ.");
        if (header["jwk"] is not JsonObject durableJwk)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Naming JWT requires header jwk.");
        var durable = SignatureKeyParser.PublicKey(durableJwk);
        var issuer = AAuthConstants.JktThumbprintUrnPrefix + durable.ComputeJwkThumbprint();
        if (SignatureKeyParser.Text(payload, "iss") != issuer)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Naming JWT issuer does not match durable key thumbprint.");
        VerifySignature(jwt, header, durable);
        var expires = ValidateTime(payload, now, clockSkew, requireIssuedAt: true);
        var confirmation = SignatureKeyParser.Confirmation(payload);
        return new(durable, confirmation, issuer, expires);
    }

    internal static DateTimeOffset ValidateTime(JsonObject payload, DateTimeOffset now, TimeSpan skew, bool requireIssuedAt)
    {
        if (payload["exp"] is not JsonValue expiration || !expiration.TryGetValue<long>(out var expires))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires integer exp.");
        DateTimeOffset expiresAt;
        try { expiresAt = DateTimeOffset.FromUnixTimeSeconds(expires); }
        catch (ArgumentOutOfRangeException exception)
        { throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT exp out of range.", exception); }
        if (expiresAt <= now - skew)
            throw new AAuthVerificationException(SignatureErrorCode.ExpiredJwt, "JWT has expired.");
        if (payload.ContainsKey("iat") || requireIssuedAt)
        {
            if (payload["iat"] is not JsonValue issuance || !issuance.TryGetValue<long>(out var issued)
                || issued > (now + skew).ToUnixTimeSeconds() || issued >= expires)
                throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT requires a valid, nonfuture iat before exp.");
        }
        return expiresAt;
    }

    internal static void VerifySignature(string jwt, JsonObject header, IAAuthKey key)
    {
        if (SignatureKeyParser.Text(header, "alg") != key.Algorithm)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT header alg must match signing key alg.");
        var segments = jwt.Split('.');
        try
        {
            var signature = Base64UrlEncoder.DecodeBytes(segments[2]);
            if (Base64UrlEncoder.Encode(signature) != segments[2]
                || !key.Verify(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]), signature))
                throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "JWT signature verification failed.");
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        { throw new AAuthVerificationException(SignatureErrorCode.InvalidJwt, "Invalid JWT signature bytes.", exception); }
    }
}