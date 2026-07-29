using System.Text;

namespace AAuth.Events.Resource;

/// <summary>
/// Raw registration preferences supplied separately from verified authorization
/// facts.
/// </summary>
/// <remarks>
/// <strong>The subscription registration signature does not bind the body
/// content.</strong> This type deliberately exposes only bounded bytes and the
/// signed content type. Applications may parse it as preferences, but must not
/// use it to widen the channel, resource, agent, ticket, or event authorization
/// established by the verified subscribe token and endpoint.
/// </remarks>
public sealed class SignatureUnboundRegistrationBody
{
    /// <summary>Creates a defensive, bounded body projection.</summary>
    public SignatureUnboundRegistrationBody(ReadOnlySpan<byte> bytes, string contentType, int maxBytes = AAuthEventsConstants.DefaultMaxBodyBytes)
    {
        if (maxBytes < 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (bytes.Length > maxBytes) throw new ArgumentException("Registration body exceeds the configured limit.", nameof(bytes));
        if (string.IsNullOrWhiteSpace(contentType)) throw new ArgumentException("Content type is required.", nameof(contentType));
        Bytes = bytes.ToArray();
        ContentType = contentType;
    }

    /// <summary>Exact received bytes; callers cannot mutate the stored array.</summary>
    public ReadOnlyMemory<byte> Bytes { get; }
    /// <summary>Alias for the exact received bytes.</summary>
    public ReadOnlyMemory<byte> RawBytes => Bytes;
    /// <summary>Exact received content type value.</summary>
    public string ContentType { get; }
    /// <summary>Decodes the bytes as UTF-8 without parsing or reserialization.</summary>
    public string GetUtf8Text() => Encoding.UTF8.GetString(Bytes.Span);
}
