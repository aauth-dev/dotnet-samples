using System;
using System.Text;

namespace AAuth.Events.Agent;

/// <summary>
/// Exact payload bytes received alongside a verified event token.
/// </summary>
/// <remarks>
/// The event JWT does not contain or bind the event payload. Consequently this
/// type is deliberately labelled unauthenticated: an AP can substitute these
/// bytes while retaining a valid event token. The bytes are suitable only for
/// display or relevance hints. Applications must re-fetch consequential
/// details from the verified resource using a normal authenticated AAuth
/// resource request; this type provides no generic re-fetch helper.
/// </remarks>
public sealed class UnauthenticatedEventPayload
{
    private readonly byte[] _bytes;

    /// <summary>Creates a defensive copy of the exact payload bytes.</summary>
    public UnauthenticatedEventPayload(ReadOnlySpan<byte> bytes, string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            throw new ArgumentException("Content type must not be empty.", nameof(contentType));
        _bytes = bytes.ToArray();
        ContentType = contentType;
    }

    /// <summary>Creates a defensive copy of the exact payload bytes.</summary>
    public UnauthenticatedEventPayload(byte[] bytes, string contentType)
        : this(bytes is null ? throw new ArgumentNullException(nameof(bytes)) : bytes.AsSpan(), contentType)
    {
    }

    /// <summary>Content type supplied with the payload.</summary>
    public string ContentType { get; }

    /// <summary>Always <see langword="false"/>; no event artifact authenticates these bytes.</summary>
    public bool IsAuthenticated => false;

    /// <summary>Always <see langword="false"/>; provided for explicit trust labelling.</summary>
    public bool IsEndToEndAuthenticated => false;

    /// <summary>Explicit trust label for UI and policy code.</summary>
    public string TrustLabel => "Unauthenticated";

    /// <summary>Returns a defensive copy of the exact bytes.</summary>
    public byte[] Bytes => (byte[])_bytes.Clone();

    /// <summary>Returns the exact bytes decoded as UTF-8 without validating a schema.</summary>
    public string GetUtf8Text() => Encoding.UTF8.GetString(_bytes);
}
