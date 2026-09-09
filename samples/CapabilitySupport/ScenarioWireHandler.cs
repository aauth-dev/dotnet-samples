using System.Text.Json.Nodes;
using AAuth.Headers;
using AAuth.HttpSig;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Samples.Capabilities;

public sealed class ScenarioWireHandler(Action<ScenarioExchange> record) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        var response = await base.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
        var scheme = request.Headers.TryGetValues("Signature-Key", out var signatureKeys)
            ? SignatureKeyHeader.Parse(signatureKeys.Single()).Scheme : null;
        var requirement = response.Headers.TryGetValues("AAuth-Requirement", out var requirements)
            ? AAuthRequirementHeader.Parse(requirements.First()).Requirement : null;
        record(new(request.Method.Method, request.RequestUri!.GetLeftPart(UriPartial.Path), (int)response.StatusCode,
            scheme, requirement, Display(body), Display(responseBody)));
        return response;
    }

    public static JsonNode? Display(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        JsonNode? json;
        try { json = JsonNode.Parse(text); }
        catch (System.Text.Json.JsonException) { return JsonValue.Create(text); }
        if (json is JsonObject body)
            foreach (var field in body.ToArray())
                if (field.Key.EndsWith("_token", StringComparison.Ordinal) && field.Value is JsonValue value
                    && value.TryGetValue<string>(out var token) && token.Split('.').Length == 3)
                    body[field.Key] = Claims(token);
        return json;
    }

    public static JsonObject Claims(string token) => JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject();
}

public sealed record ScenarioExchange(string Method, string Url, int Status, string? Scheme, string? Requirement,
    JsonNode? Request, JsonNode? Response);