namespace AAuth.Events.Resource;

/// <summary>
/// Immutable logical event delivery. Reusing this instance performs an exact
/// retry; preparing another instance creates another event token and
/// identifier.
/// </summary>
public sealed class PreparedEventDelivery
{
    private readonly byte[] _payload;

    internal PreparedEventDelivery(
        string compactToken,
        string tokenId,
        string apIssuer,
        DateTimeOffset expiresAt,
        byte[]? payload,
        string? contentType)
    {
        if (string.IsNullOrWhiteSpace(compactToken))
            throw new ArgumentException("A compact event token is required.", nameof(compactToken));
        if (string.IsNullOrWhiteSpace(tokenId))
            throw new ArgumentException("An event token identifier is required.", nameof(tokenId));
        if (string.IsNullOrWhiteSpace(apIssuer))
            throw new ArgumentException("An AP issuer is required.", nameof(apIssuer));
        if (expiresAt <= DateTimeOffset.MinValue)
            throw new ArgumentOutOfRangeException(nameof(expiresAt));

        _payload = payload is null ? Array.Empty<byte>() : (byte[])payload.Clone();
        if (_payload.Length == 0)
        {
            if (contentType is not null)
                throw new ArgumentException("Bodyless deliveries must not have a content type.", nameof(contentType));
            contentType = null;
        }
        else if (!string.Equals(contentType, AAuthEventsConstants.JsonMediaType, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Non-empty event payloads require Content-Type: application/json.",
                nameof(contentType));
        }

        CompactToken = compactToken;
        TokenId = tokenId;
        ApIssuer = apIssuer;
        ExpiresAt = expiresAt;
        ContentType = contentType;
    }

    /// <summary>The exact compact event JWT reused by every retry.</summary>
    public string CompactToken { get; }
    /// <summary>The event JWT's fresh <c>jti</c>.</summary>
    public string TokenId { get; }
    /// <summary>Alias for <see cref="TokenId"/>.</summary>
    public string Jti => TokenId;
    internal string ApIssuer { get; }
    /// <summary>The event JWT expiry.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary><c>application/json</c> for a payload, otherwise null.</summary>
    public string? ContentType { get; }

    /// <summary>Returns a defensive copy of the exact UTF-8 payload bytes.</summary>
    public byte[] GetPayloadBytes() => (byte[])_payload.Clone();

    internal ReadOnlyMemory<byte> Payload => _payload;
    internal bool HasPayload => _payload.Length != 0;
}
