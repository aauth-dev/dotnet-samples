using System.Security.Cryptography;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events.Internal;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tokens;

/// <summary>Builds a resource-issued AAuth Events event token.</summary>
public sealed class EventTokenBuilder
{
    /// <summary>The JWT type emitted by this builder.</summary>
    public const string TokenType = AAuthEventsConstants.EventTokenType;
    /// <summary>The fixed domain/key value emitted by this builder.</summary>
    public const string ResourceDwk = AAuthEventsConstants.ResourceDwk;
    /// <summary>Resource URL in the <c>iss</c> claim.</summary>
    public required string Issuer { get; init; }
    /// <summary>Agent identifier in the <c>aud</c> claim.</summary>
    public required string Audience { get; init; }
    /// <summary>Subscription identifier in the <c>eid</c> claim.</summary>
    public required string Eid { get; init; }
    /// <summary>Resource signing key identifier.</summary>
    public required string KeyId { get; init; }
    /// <summary>Resource private signing key.</summary>
    public required IAAuthKey Key { get; init; }
    /// <summary>Token lifetime.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>Issue time, defaulting to the current UTC time.</summary>
    public DateTimeOffset? IssuedAt { get; init; }
    /// <summary>Explicit event token identifier; otherwise a fresh 128-bit value is generated.</summary>
    public string? Jti { get; init; }
    /// <summary>Alias for <see cref="Jti"/>.</summary>
    public string? TokenId { get; init; }

    /// <summary>Builds and signs the token.</summary>
    public EventTokenArtifact Build()
    {
        SubscribeTokenBuilder.Require(Issuer, nameof(Issuer));
        SubscribeTokenBuilder.Require(Audience, nameof(Audience));
        SubscribeTokenBuilder.Require(Eid, nameof(Eid));
        SubscribeTokenBuilder.Require(KeyId, nameof(KeyId));
        SubscribeTokenBuilder.RequireUrl(Issuer, nameof(Issuer));
        SubscribeTokenBuilder.RequireKey(Key);
        SubscribeTokenBuilder.EnsureAlgorithm(Key);
        if (Lifetime <= TimeSpan.Zero)
            throw new InvalidOperationException("Lifetime must be positive.");

        var issuedAt = IssuedAt ?? DateTimeOffset.UtcNow;
        var iat = issuedAt.ToUnixTimeSeconds();
        var exp = (issuedAt + Lifetime).ToUnixTimeSeconds();
        if (exp <= iat)
            throw new InvalidOperationException("Lifetime must produce exp greater than iat.");

        var jti = Jti ?? TokenId;
        if (Jti is not null && TokenId is not null && Jti != TokenId)
            throw new InvalidOperationException("Jti and TokenId must match when both are supplied.");
        if (jti is null)
            jti = NewId();
        else
            SubscribeTokenBuilder.Require(jti, nameof(Jti));

        var header = new JsonObject
        {
            [AAuthEventsConstants.AlgorithmClaim] = Key.Algorithm,
            [AAuthEventsConstants.TypeClaim] = AAuthEventsConstants.EventTokenType,
            [AAuthEventsConstants.KeyIdClaim] = KeyId,
        };
        var payload = new JsonObject
        {
            [AAuthEventsConstants.IssuerClaim] = Issuer,
            [AAuthEventsConstants.DomainKeyClaim] = AAuthEventsConstants.ResourceDwk,
            [AAuthEventsConstants.AudienceClaim] = Audience,
            [AAuthEventsConstants.EventIdClaim] = Eid,
            [AAuthEventsConstants.IssuedAtClaim] = iat,
            [AAuthEventsConstants.ExpiresAtClaim] = exp,
            [AAuthEventsConstants.TokenIdClaim] = jti,
        };
        return new EventTokenArtifact(EventsJwtWriter.SignCompact(header, payload, Key), jti);
    }

    private static string NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes.ToArray());
    }
}

/// <summary>The compact event token and its per-event identifier.</summary>
public sealed record EventTokenArtifact(string CompactToken, string Jti)
{
    /// <summary>The compact serialized JWT.</summary>
    public string Token => CompactToken;
    /// <summary>The event token identifier.</summary>
    public string TokenId => Jti;
}
