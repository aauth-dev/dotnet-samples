using System.Security.Cryptography;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events.Internal;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tokens;

/// <summary>Builds an AP-issued AAuth Events subscribe token.</summary>
public sealed class SubscribeTokenBuilder
{
    /// <summary>The JWT type emitted by this builder.</summary>
    public const string TokenType = AAuthEventsConstants.SubscribeTokenType;
    /// <summary>The fixed domain/key value emitted by this builder.</summary>
    public const string AgentDwk = AAuthEventsConstants.AgentDwk;
    /// <summary>AP URL in the <c>iss</c> claim.</summary>
    public required string Issuer { get; init; }
    /// <summary>Subscribing agent identifier in the <c>sub</c> claim.</summary>
    public required string Subject { get; init; }
    /// <summary>Resource URL in the <c>aud</c> claim.</summary>
    public required string Audience { get; init; }
    /// <summary>AP signing key identifier.</summary>
    public required string KeyId { get; init; }
    /// <summary>AP private signing key.</summary>
    public required IAAuthKey Key { get; init; }
    /// <summary>Agent HTTP-signature confirmation key; defaults to <see cref="Key"/>.</summary>
    public IAAuthKey? ConfirmationKey { get; init; }
    /// <summary>Token lifetime.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);
    /// <summary>Issue time, defaulting to the current UTC time.</summary>
    public DateTimeOffset? IssuedAt { get; init; }
    /// <summary>Explicit event identifier; when omitted, a fresh 128-bit value is generated.</summary>
    public string? EventId { get; init; }
    /// <summary>Alias for <see cref="EventId"/>.</summary>
    public string? Eid { get; init; }
    /// <summary>Optional positive event-use limit.</summary>
    public long? MaxUses { get; init; }

    /// <summary>Builds and signs the token.</summary>
    public SubscribeTokenArtifact Build()
    {
        Require(Issuer, nameof(Issuer));
        Require(Subject, nameof(Subject));
        Require(Audience, nameof(Audience));
        Require(KeyId, nameof(KeyId));
        RequireUrl(Issuer, nameof(Issuer));
        RequireUrl(Audience, nameof(Audience));
        RequireKey(Key);
        EnsureAlgorithm(Key);
        if (Lifetime <= TimeSpan.Zero)
            throw new InvalidOperationException("Lifetime must be positive.");
        if (MaxUses is <= 0)
            throw new InvalidOperationException("MaxUses must be positive when supplied.");

        var issuedAt = IssuedAt ?? DateTimeOffset.UtcNow;
        var iat = issuedAt.ToUnixTimeSeconds();
        var exp = (issuedAt + Lifetime).ToUnixTimeSeconds();
        if (exp <= iat)
            throw new InvalidOperationException("Lifetime must produce exp greater than iat.");

        var eid = EventId ?? Eid;
        if (EventId is not null && Eid is not null && EventId != Eid)
            throw new InvalidOperationException("EventId and Eid must match when both are supplied.");
        if (eid is null)
            eid = NewId();
        else
            Require(eid, nameof(EventId));

        var confirmationKey = ConfirmationKey ?? Key;
        if (confirmationKey is null)
            throw new InvalidOperationException("ConfirmationKey must be set.");
        EnsureAlgorithm(confirmationKey);

        var header = new JsonObject
        {
            [AAuthEventsConstants.AlgorithmClaim] = Key.Algorithm,
            [AAuthEventsConstants.TypeClaim] = AAuthEventsConstants.SubscribeTokenType,
            [AAuthEventsConstants.KeyIdClaim] = KeyId,
        };
        var payload = new JsonObject
        {
            [AAuthEventsConstants.IssuerClaim] = Issuer,
            [AAuthEventsConstants.DomainKeyClaim] = AAuthEventsConstants.AgentDwk,
            [AAuthEventsConstants.SubjectClaim] = Subject,
            [AAuthEventsConstants.AudienceClaim] = Audience,
            [AAuthEventsConstants.ConfirmationClaim] = new JsonObject
            {
                [AAuthEventsConstants.JwkClaim] = confirmationKey.ToPublicJwk(),
            },
            [AAuthEventsConstants.EventIdClaim] = eid,
            [AAuthEventsConstants.IssuedAtClaim] = iat,
            [AAuthEventsConstants.ExpiresAtClaim] = exp,
        };
        if (MaxUses is not null)
            payload[AAuthEventsConstants.MaxUsesClaim] = MaxUses.Value;

        return new SubscribeTokenArtifact(
            EventsJwtWriter.SignCompact(header, payload, Key), eid);
    }

    private static string NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes.ToArray());
    }

    internal static void RequireKey(IAAuthKey? key)
    {
        if (key is null)
            throw new InvalidOperationException("Key must be set.");
        if (!key.HasPrivateKey)
            throw new InvalidOperationException("Signing key must include a private component.");
    }

    internal static void EnsureAlgorithm(IAAuthKey key)
    {
        if (key.Algorithm is not "EdDSA" and not "ES256")
            throw new InvalidOperationException($"Unsupported signing algorithm '{key.Algorithm}'.");
    }

    internal static void Require(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"{name} must be a non-empty string.");
    }

    internal static void RequireUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            throw new InvalidOperationException($"{name} must be an absolute https:// URL (or http://localhost).");
    }
}

/// <summary>The compact subscribe token and its subscription event identifier.</summary>
public sealed record SubscribeTokenArtifact(string CompactToken, string Eid)
{
    /// <summary>The compact serialized JWT.</summary>
    public string Token => CompactToken;
    /// <summary>The event identifier.</summary>
    public string EventId => Eid;
}
