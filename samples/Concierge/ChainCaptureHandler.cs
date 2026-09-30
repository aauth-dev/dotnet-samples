using System.Text.Json.Nodes;
using AAuth.HttpSig;

namespace Concierge;

/// <summary>
/// The Concierge agent's transport: records each downstream exchange into the capture of the
/// inbound request that caused it (<see cref="Begin"/>), so one shared agent serves every request.
/// </summary>
public sealed class ChainCaptureHandler : DelegatingHandler
{
    private static readonly AsyncLocal<List<ChainExchange>?> Current = new();

    /// <summary>Start capturing the exchanges of the current inbound request.</summary>
    public static List<ChainExchange> Begin() => Current.Value = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var fields = request.Content is null ? [] : JsonNode.Parse(
            await request.Content.ReadAsStringAsync(cancellationToken))?.AsObject().Select(field => field.Key).ToArray() ?? [];
        var scheme = request.Headers.TryGetValues("Signature-Key", out var values)
            ? SignatureKeyHeader.Parse(values.Single()).Scheme : null;
        var response = await base.SendAsync(request, cancellationToken);
        if (Current.Value is { } exchanges)
            lock (exchanges) exchanges.Add(new(request.Method.Method, request.RequestUri!.AbsoluteUri, scheme, fields, (int)response.StatusCode));
        return response;
    }
}

public sealed record ChainExchange(string Method, string Url, string? Scheme, string[] Fields, int Status);