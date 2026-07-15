using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Identifiers;
using AAuth.Tokens;

namespace AAuth.Events.Tokens;

/// <summary>Strongly typed claims from a verified subscribe token.</summary>
public sealed record SubscribeTokenClaims(
    string Issuer,
    string Subject,
    string Audience,
    IAAuthKey ConfirmationKey,
    string Eid,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    long? MaxUses,
    string KeyId)
{
    /// <summary>Issued-at Unix timestamp.</summary>
    public long IssuedAtUnixSeconds => IssuedAt.ToUnixTimeSeconds();
    /// <summary>Expiration Unix timestamp.</summary>
    public long ExpiresAtUnixSeconds => ExpiresAt.ToUnixTimeSeconds();
    /// <summary>Alias for <see cref="Eid"/>.</summary>
    public string EventId => Eid;

    /// <summary>Reads and validates all required Events claims.</summary>
    public static SubscribeTokenClaims Read(TokenVerifier.VerifiedToken verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        EventsClaimValidation.ValidateHeader(
            verified, AAuthEventsConstants.SubscribeTokenType, AAuthEventsConstants.AgentDwk);

        var payload = verified.Payload;
        var issuer = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.IssuerClaim);
        var subject = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.SubjectClaim);
        var audience = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.AudienceClaim);
        var eid = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.EventIdClaim);
        EventsClaimValidation.RequireAgentId(subject, AAuthEventsConstants.SubjectClaim);
        EventsClaimValidation.RequireUrl(issuer, AAuthEventsConstants.IssuerClaim);
        EventsClaimValidation.RequireUrl(audience, AAuthEventsConstants.AudienceClaim);

        var cnf = payload[AAuthEventsConstants.ConfirmationClaim] as JsonObject
            ?? throw EventsClaimValidation.Error("Subscribe token is missing 'cnf'.");
        var jwk = cnf[AAuthEventsConstants.JwkClaim] as JsonObject
            ?? throw EventsClaimValidation.Error("Subscribe token is missing 'cnf.jwk'.");
        IAAuthKey confirmationKey;
        try
        {
            confirmationKey = KeyFactory.FromJwk(jwk);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            throw EventsClaimValidation.Error("Subscribe token 'cnf.jwk' is not a supported key.", ex);
        }

        var iat = EventsClaimValidation.RequiredUnixTime(payload, AAuthEventsConstants.IssuedAtClaim);
        var exp = EventsClaimValidation.RequiredUnixTime(payload, AAuthEventsConstants.ExpiresAtClaim);
        if (exp <= iat)
            throw EventsClaimValidation.Error("'exp' must be greater than 'iat'.");

        long? maxUses = null;
        if (payload.ContainsKey(AAuthEventsConstants.MaxUsesClaim))
        {
            maxUses = EventsClaimValidation.RequiredInteger(payload, AAuthEventsConstants.MaxUsesClaim);
            if (maxUses <= 0)
                throw EventsClaimValidation.Error("'max_uses' must be positive.");
        }

        return new SubscribeTokenClaims(
            issuer,
            subject,
            audience,
            confirmationKey,
            eid,
            EventsClaimValidation.ToDateTime(iat, AAuthEventsConstants.IssuedAtClaim),
            EventsClaimValidation.ToDateTime(exp, AAuthEventsConstants.ExpiresAtClaim),
            maxUses,
            EventsClaimValidation.RequiredHeaderString(verified, AAuthEventsConstants.KeyIdClaim));
    }

    /// <summary>Alias for <see cref="Read"/>.</summary>
    public static SubscribeTokenClaims FromVerifiedToken(TokenVerifier.VerifiedToken verified) => Read(verified);
}

internal static class EventsClaimValidation
{
    public static void ValidateHeader(TokenVerifier.VerifiedToken token, string type, string dwk)
    {
        if (token.TokenType != type ||
            (string?)token.Header[AAuthEventsConstants.TypeClaim] != type)
            throw Error($"Token type must be '{type}'.");
        var alg = RequiredHeaderString(token, AAuthEventsConstants.AlgorithmClaim);
        if (alg is not "EdDSA" and not "ES256")
            throw Error($"Unsupported token algorithm '{alg}'.");
        if ((string?)token.Payload[AAuthEventsConstants.DomainKeyClaim] != dwk)
            throw Error($"Token 'dwk' must be '{dwk}'.");
    }

    public static string RequiredHeaderString(TokenVerifier.VerifiedToken token, string name) =>
        RequiredString(token.Header, name, $"Token header is missing '{name}'.");

    public static string RequiredString(JsonObject payload, string name) =>
        RequiredString(payload, name, $"Token is missing '{name}'.");

    private static string RequiredString(JsonObject payload, string name, string message)
    {
        var value = payload[name];
        if (value is not JsonValue jsonValue ||
            !jsonValue.TryGetValue<string>(out var result) ||
            string.IsNullOrWhiteSpace(result))
            throw Error($"{message} It must be a non-empty string.");
        return result;
    }

    public static long RequiredUnixTime(JsonObject payload, string name)
    {
        var value = RequiredInteger(payload, name);
        try
        {
            _ = DateTimeOffset.FromUnixTimeSeconds(value);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw Error($"Token claim '{name}' is outside the Unix time range.", ex);
        }
        return value;
    }

    public static long RequiredInteger(JsonObject payload, string name)
    {
        if (payload[name] is JsonValue value && value.TryGetValue<long>(out var result))
            return result;
        throw Error($"Token claim '{name}' must be an integer.");
    }

    public static DateTimeOffset ToDateTime(long seconds, string name)
    {
        try { return DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch (ArgumentOutOfRangeException ex) { throw Error($"Token claim '{name}' is invalid.", ex); }
    }

    public static void RequireUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            throw Error($"{name} must be an absolute https:// URL (or loopback http:// URL).");
    }

    public static void RequireAgentId(string value, string name)
    {
        if (!AgentId.TryParse(value, out _, out var error))
            throw Error($"Token claim '{name}' must be a valid AAuth agent identifier: {error}");
    }

    public static TokenVerificationException Error(string message) => new(message);
    public static TokenVerificationException Error(string message, Exception inner) => new(message, inner);
}
