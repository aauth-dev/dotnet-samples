using System.Security.Cryptography;
using System.Text;
using AAuth.Events.Tokens;

namespace AAuth.Events.AgentProvider;

/// <summary>
/// An event whose envelope and HTTP body have been verified by the AP endpoint.
/// </summary>
public sealed class IncomingEvent
{
    private readonly byte[] _tokenHash;
    private readonly byte[] _rawPayload;
    private readonly byte[]? _contentDigest;

    /// <summary>Convenience overload for a nullable digest.</summary>
    public IncomingEvent(
        string compactToken,
        EventTokenClaims claims,
        byte[] rawPayload,
        string? contentType = null,
        byte[]? contentDigest = null,
        DateTimeOffset? receiptTime = null)
    {
        if (string.IsNullOrWhiteSpace(compactToken)) throw new ArgumentException("The compact token is required.", nameof(compactToken));
        ArgumentNullException.ThrowIfNull(claims);
        CompactToken = compactToken;
        Claims = claims;
        Jti = claims.Jti;
        _tokenHash = SHA256.HashData(Encoding.ASCII.GetBytes(compactToken));
        _rawPayload = (rawPayload ?? throw new ArgumentNullException(nameof(rawPayload))).ToArray();
        _contentDigest = contentDigest?.ToArray();
        ContentType = contentType;
        ReceiptTime = receiptTime ?? DateTimeOffset.UtcNow;
    }

    /// <summary>The exact compact JWT received in the Signature-Key header.</summary>
    public string CompactToken { get; }
    /// <summary>SHA-256 of the ASCII compact JWT.</summary>
    public byte[] TokenHash => _tokenHash.ToArray();
    /// <summary>Lowercase-independent hexadecimal token hash for database keys.</summary>
    public string TokenHashHex => Convert.ToHexString(_tokenHash);
    /// <summary>The required event-token <c>jti</c>.</summary>
    public string Jti { get; }
    /// <summary>Typed, cryptographically verified event claims.</summary>
    public EventTokenClaims Claims { get; }
    /// <summary>Exact unparsed body bytes. The event token does not authenticate them.</summary>
    public byte[] RawPayloadBytes => _rawPayload.ToArray();
    /// <summary>Alias for <see cref="RawPayloadBytes"/>.</summary>
    public byte[] RawPayload => RawPayloadBytes;
    /// <summary>The received media type, if present.</summary>
    public string? ContentType { get; }
    /// <summary>The verified SHA-256 Content-Digest, if present.</summary>
    public byte[]? ContentDigest => _contentDigest?.ToArray();
    /// <summary>When the AP completed request verification.</summary>
    public DateTimeOffset ReceiptTime { get; }
    /// <summary>Alias for <see cref="ReceiptTime"/>.</summary>
    public DateTimeOffset ReceivedAt => ReceiptTime;
}
