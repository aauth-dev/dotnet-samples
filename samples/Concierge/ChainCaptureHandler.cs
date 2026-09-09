using System.Text.Json.Nodes;
using AAuth.HttpSig;

namespace Concierge;

public sealed class ChainCaptureHandler : DelegatingHandler
{
    public List<ChainExchange> Exchanges { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var fields = request.Content is null ? [] : JsonNode.Parse(
            await request.Content.ReadAsStringAsync(cancellationToken))?.AsObject().Select(field => field.Key).ToArray() ?? [];
        var scheme = request.Headers.TryGetValues("Signature-Key", out var values)
            ? SignatureKeyHeader.Parse(values.Single()).Scheme : null;
        var response = await base.SendAsync(request, cancellationToken);
        Exchanges.Add(new(request.Method.Method, request.RequestUri!.AbsoluteUri, scheme, fields, (int)response.StatusCode));
        return response;
    }
}

public sealed record ChainExchange(string Method, string Url, string? Scheme, string[] Fields, int Status);