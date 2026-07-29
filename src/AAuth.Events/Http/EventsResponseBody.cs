using System.Buffers;
using System.Text;

namespace AAuth.Events.Http;

internal static class EventsResponseBody
{
    public static async Task<string?> ReadUtf8Async(
        HttpContent? content,
        int maxBytes = AAuthEventsConstants.DefaultMaxBodyBytes,
        CancellationToken cancellationToken = default)
    {
        if (content is null)
            return null;
        if (maxBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (content.Headers.ContentLength is > 0 &&
            content.Headers.ContentLength.Value > maxBytes)
            throw new EventsResponseBodyTooLargeException(maxBytes);

        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(maxBytes, 81920));
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            var total = 0;
            while (true)
            {
                var read = await stream.ReadAsync(
                    buffer.AsMemory(0, buffer.Length),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                if (read > maxBytes - total)
                    throw new EventsResponseBodyTooLargeException(maxBytes);
                output.Write(buffer, 0, read);
                total += read;
            }
            return Encoding.UTF8.GetString(output.ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}

internal sealed class EventsResponseBodyTooLargeException(int maxBytes)
    : Exception($"Events response body exceeds the {maxBytes} byte limit.");
