using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.Http;

/// <summary>Raw request body and its verified SHA-256 digest.</summary>
public sealed record EventsRequestBodyResult(byte[] Bytes, bool HasContentDigest);

/// <summary>Bounded body buffering and RFC 9530 Content-Digest helpers.</summary>
public static class EventsRequestBody
{
    /// <summary>Reads content without parsing or reserializing it.</summary>
    public static async Task<byte[]> ReadAsync(
        HttpRequestMessage request,
        int maxBytes = AAuthEventsConstants.DefaultMaxBodyBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (maxBytes < 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (request.Content is null) return Array.Empty<byte>();
        await using var stream = await request.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(maxBytes, 81920));
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            var total = 0;
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0) break;
                if (read > maxBytes - total)
                    throw new EventsVerificationException(
                        EventsVerificationErrorCode.BodyTooLarge,
                        $"Request body exceeds the {maxBytes} byte limit.");
                output.Write(buffer, 0, read);
                total += read;
            }
            return output.ToArray();
        }
        catch (EventsVerificationException)
        {
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Reads a bounded body and verifies its RFC 9530 digest.</summary>
    public static async Task<EventsRequestBodyResult> ReadAndVerifyAsync(
        HttpRequestMessage request,
        int maxBytes = AAuthEventsConstants.DefaultMaxBodyBytes,
        CancellationToken cancellationToken = default)
    {
        var bytes = await ReadAsync(request, maxBytes, cancellationToken).ConfigureAwait(false);
        var digest = GetSha256Digest(request);
        if (digest is null)
            return new EventsRequestBodyResult(bytes, false);
        VerifyDigest(bytes, digest);
        return new EventsRequestBodyResult(bytes, true);
    }

    /// <summary>Returns the sole sha-256 dictionary member, or null when absent.</summary>
    public static byte[]? GetSha256Digest(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Content is null || !request.Content.Headers.Contains("Content-Digest")) return null;
        var values = request.Content.Headers.GetValues("Content-Digest");
        var fields = new List<string>();
        foreach (var value in values)
            fields.Add(value);
        if (fields.Count == 0) return null;
        if (fields.Count != 1)
            throw InvalidDigest("Content-Digest must contain exactly one field value.");
        return ParseSha256Digest(fields[0]);
    }

    /// <summary>Parses exactly one RFC 9530 sha-256 member.</summary>
    public static byte[] ParseSha256Digest(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw InvalidDigest("Content-Digest is empty.");
        var text = value.Trim();
        var equals = text.IndexOf('=');
        if (equals <= 0)
            throw InvalidDigest("Content-Digest must contain one dictionary member.");
        var name = text[..equals].Trim();
        if (!string.Equals(name, "sha-256", StringComparison.Ordinal))
            throw InvalidDigest("Only the sha-256 Content-Digest member is supported.");
        var encoded = text[(equals + 1)..].Trim();
        if (encoded.Contains(',') || encoded.Length < 2 || encoded[0] != ':' || encoded[^1] != ':' ||
            encoded[1..^1].Contains(':'))
            throw InvalidDigest("sha-256 must be an RFC 9530 byte sequence.");
        var encodedBytes = encoded[1..^1];
        foreach (var c in encodedBytes)
            if (!(char.IsLetterOrDigit(c) || c is '+' or '/' or '='))
                throw InvalidDigest("sha-256 contains invalid base64 characters.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(encodedBytes); }
        catch (FormatException ex) { throw InvalidDigest("sha-256 is not valid base64.", ex); }
        if (bytes.Length != 32)
            throw InvalidDigest("sha-256 must contain exactly 32 bytes.");
        return bytes;
    }

    /// <summary>Alias for <see cref="ParseSha256Digest"/>.</summary>
    public static byte[] ParseContentDigest(string value) => ParseSha256Digest(value);

    /// <summary>Compares a declared digest with exact body bytes in constant time.</summary>
    public static void VerifyDigest(ReadOnlySpan<byte> body, ReadOnlySpan<byte> digest)
    {
        var expected = SHA256.HashData(body);
        if (!CryptographicOperations.FixedTimeEquals(expected, digest))
            throw new EventsVerificationException(
                EventsVerificationErrorCode.ContentDigestMismatch,
                "Content-Digest does not match the exact request bytes.");
    }

    private static EventsVerificationException InvalidDigest(string detail, Exception? inner = null) =>
        new(EventsVerificationErrorCode.InvalidContentDigest, detail, inner);
}
