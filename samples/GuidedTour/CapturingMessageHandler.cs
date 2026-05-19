using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GuidedTour;

/// <summary>
/// <see cref="DelegatingHandler"/> that captures the last outbound request
/// and inbound response so the tour UI can render them after the call
/// returns. The response body is buffered and re-attached so downstream
/// code can still read it.
/// </summary>
public sealed class CapturingMessageHandler : DelegatingHandler
{
    /// <summary>The most recent exchange, or null if no request has been sent yet.</summary>
    public CapturedExchange? Last { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var requestHeaders = HeaderFormatter.Format(request.Headers, request.Content?.Headers);
        var requestBody = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var response = await base.SendAsync(request, cancellationToken);

        var responseHeaders = HeaderFormatter.Format(response.Headers, response.Content.Headers);
        var bodyBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        // Honor the response's declared charset; fall back to UTF-8 for
        // unmarked text and JSON. Non-text payloads (e.g. binary) get a
        // base64 rendering so the tour UI doesn't show mojibake.
        var responseBody = DecodeBody(bodyBytes, response.Content.Headers);

        // Rebuild the content so the buffered bytes remain readable downstream.
        var oldContentHeaders = response.Content.Headers;
        var rebuilt = new ByteArrayContent(bodyBytes);
        foreach (var h in oldContentHeaders)
        {
            rebuilt.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }
        response.Content = rebuilt;

        Last = new CapturedExchange(
            $"{request.Method} {request.RequestUri?.PathAndQuery}",
            requestHeaders,
            requestBody,
            $"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}",
            responseHeaders,
            responseBody);

        return response;
    }

    private static string DecodeBody(byte[] bytes, System.Net.Http.Headers.HttpContentHeaders headers)
    {
        if (bytes.Length == 0) { return string.Empty; }
        var mediaType = headers.ContentType?.MediaType;
        var isTextual = mediaType is null
            || mediaType.StartsWith("text/", System.StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("application/json", System.StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith("+json", System.StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("application/x-www-form-urlencoded", System.StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("application/jwk-set+json", System.StringComparison.OrdinalIgnoreCase);
        if (!isTextual)
        {
            return $"[{bytes.Length} bytes, {mediaType}]\n{System.Convert.ToBase64String(bytes)}";
        }
        try
        {
            var charset = headers.ContentType?.CharSet;
            var encoding = string.IsNullOrEmpty(charset)
                ? System.Text.Encoding.UTF8
                : System.Text.Encoding.GetEncoding(charset);
            return encoding.GetString(bytes);
        }
        catch (System.ArgumentException)
        {
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
    }
}

/// <summary>Captured request/response pair for tour rendering.</summary>
public sealed record CapturedExchange(
    string RequestLine,
    string RequestHeaders,
    string? RequestBody,
    string StatusLine,
    string ResponseHeaders,
    string ResponseBody);

internal static class HeaderFormatter
{
    public static string Format(
        System.Net.Http.Headers.HttpHeaders headers,
        System.Net.Http.Headers.HttpContentHeaders? contentHeaders)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var h in headers)
        {
            foreach (var v in h.Value)
            {
                sb.Append(h.Key).Append(": ").AppendLine(v);
            }
        }
        if (contentHeaders is not null)
        {
            foreach (var h in contentHeaders)
            {
                foreach (var v in h.Value)
                {
                    sb.Append(h.Key).Append(": ").AppendLine(v);
                }
            }
        }
        return sb.ToString().TrimEnd();
    }
}
