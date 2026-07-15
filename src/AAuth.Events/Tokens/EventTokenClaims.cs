using AAuth.Tokens;

namespace AAuth.Events.Tokens;

/// <summary>Strongly typed claims from a verified event token.</summary>
public sealed record EventTokenClaims(
    string Issuer,
    string Audience,
    string Eid,
    string Jti,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string KeyId)
{
    /// <summary>Issued-at Unix timestamp.</summary>
    public long IssuedAtUnixSeconds => IssuedAt.ToUnixTimeSeconds();
    /// <summary>Expiration Unix timestamp.</summary>
    public long ExpiresAtUnixSeconds => ExpiresAt.ToUnixTimeSeconds();
    /// <summary>Alias for <see cref="Jti"/>.</summary>
    public string TokenId => Jti;
    /// <summary>Alias for <see cref="Eid"/>.</summary>
    public string EventId => Eid;

    /// <summary>Reads and validates all required Events claims.</summary>
    public static EventTokenClaims Read(TokenVerifier.VerifiedToken verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        EventsClaimValidation.ValidateHeader(
            verified, AAuthEventsConstants.EventTokenType, AAuthEventsConstants.ResourceDwk);

        var payload = verified.Payload;
        var issuer = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.IssuerClaim);
        var audience = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.AudienceClaim);
        var eid = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.EventIdClaim);
        var jti = EventsClaimValidation.RequiredString(payload, AAuthEventsConstants.TokenIdClaim);
        EventsClaimValidation.RequireUrl(issuer, AAuthEventsConstants.IssuerClaim);
        EventsClaimValidation.RequireAgentId(audience, AAuthEventsConstants.AudienceClaim);

        var iat = EventsClaimValidation.RequiredUnixTime(payload, AAuthEventsConstants.IssuedAtClaim);
        var exp = EventsClaimValidation.RequiredUnixTime(payload, AAuthEventsConstants.ExpiresAtClaim);
        if (exp <= iat)
            throw EventsClaimValidation.Error("'exp' must be greater than 'iat'.");

        return new EventTokenClaims(
            issuer,
            audience,
            eid,
            jti,
            EventsClaimValidation.ToDateTime(iat, AAuthEventsConstants.IssuedAtClaim),
            EventsClaimValidation.ToDateTime(exp, AAuthEventsConstants.ExpiresAtClaim),
            EventsClaimValidation.RequiredHeaderString(verified, AAuthEventsConstants.KeyIdClaim));
    }

    /// <summary>Alias for <see cref="Read"/>.</summary>
    public static EventTokenClaims FromVerifiedToken(TokenVerifier.VerifiedToken verified) => Read(verified);
}
