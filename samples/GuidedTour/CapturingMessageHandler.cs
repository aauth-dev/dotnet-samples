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
        var responseBody = System.Text.Encoding.UTF8.GetString(bodyBytes);

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
