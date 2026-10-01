using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
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
    internal bool ShowSensitiveProtocolArtifacts { get; init; }

    /// <summary>The most recent exchange, or null if no request has been sent yet.</summary>
    public CapturedExchange? Last { get; private set; }

    /// <summary>All captured exchanges in order.</summary>
    public List<CapturedExchange> All { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var rawRequestHeaders = HeaderFormatter.Format(request.Headers, request.Content?.Headers, showSensitiveProtocolArtifacts: true);
        var requestHeaders = HeaderFormatter.Format(request.Headers, request.Content?.Headers, ShowSensitiveProtocolArtifacts);
        var requestBody = request.Content is null
            ? null
            : ProtocolArtifactRedactor.RedactText(await request.Content.ReadAsStringAsync(cancellationToken), ShowSensitiveProtocolArtifacts);

        var response = await base.SendAsync(request, cancellationToken);

        var rawResponseHeaders = HeaderFormatter.Format(response.Headers, response.Content.Headers, showSensitiveProtocolArtifacts: true);
        var responseHeaders = HeaderFormatter.Format(response.Headers, response.Content.Headers, ShowSensitiveProtocolArtifacts);
        var bodyBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        // Honor the response's declared charset; fall back to UTF-8 for
        // unmarked text and JSON. Non-text payloads (e.g. binary) get a
        // base64 rendering so the tour UI doesn't show mojibake.
        var rawResponseBody = DecodeBody(bodyBytes, response.Content.Headers);
        var responseBody = ProtocolArtifactRedactor.RedactText(
            rawResponseBody,
            ShowSensitiveProtocolArtifacts) ?? string.Empty;

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
            rawRequestHeaders,
            requestBody,
            $"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}",
            responseHeaders,
            rawResponseHeaders,
            responseBody,
            rawResponseBody);

        All.Add(Last);

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
    string RawRequestHeaders,
    string? RequestBody,
    string StatusLine,
    string ResponseHeaders,
    string RawResponseHeaders,
    string ResponseBody,
    string RawResponseBody);

internal static class HeaderFormatter
{
    public static string Format(
        System.Net.Http.Headers.HttpHeaders headers,
        System.Net.Http.Headers.HttpContentHeaders? contentHeaders,
        bool showSensitiveProtocolArtifacts = false)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var h in headers)
        {
            foreach (var v in h.Value)
            {
                sb.Append(h.Key).Append(": ").AppendLine(ProtocolArtifactRedactor.RedactHeader(h.Key, v, showSensitiveProtocolArtifacts));
            }
        }
        if (contentHeaders is not null)
        {
            foreach (var h in contentHeaders)
            {
                foreach (var v in h.Value)
                {
                    sb.Append(h.Key).Append(": ").AppendLine(ProtocolArtifactRedactor.RedactHeader(h.Key, v, showSensitiveProtocolArtifacts));
                }
            }
        }
        return sb.ToString().TrimEnd();
    }
}

internal static partial class ProtocolArtifactRedactor
{
    private const string Redacted = "[redacted protocol credential; enable GuidedTour:ShowSensitiveProtocolArtifacts only for local debugging]";
    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization",
        "Signature-Key",
        "AAuth-Requirement",
        "AAuth-Access",
    };

    public static string RedactHeader(string name, string value, bool showSensitiveProtocolArtifacts)
        => !showSensitiveProtocolArtifacts && SensitiveHeaders.Contains(name)
            ? Redacted
            : RedactText(value, showSensitiveProtocolArtifacts) ?? string.Empty;

    public static string? RedactToken(string? value, bool showSensitiveProtocolArtifacts)
        => string.IsNullOrWhiteSpace(value) || showSensitiveProtocolArtifacts ? value : Redacted;

    public static string? RedactDecoded(string? value, bool showSensitiveProtocolArtifacts)
        => string.IsNullOrWhiteSpace(value) || showSensitiveProtocolArtifacts ? value : RedactText(value, false);

    public static string? RedactText(string? value, bool showSensitiveProtocolArtifacts)
        => string.IsNullOrEmpty(value) || showSensitiveProtocolArtifacts
            ? value
            : CompactJwtRegex().Replace(value, "[redacted compact JWT]");

    [GeneratedRegex(@"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])")]
    private static partial Regex CompactJwtRegex();
}
