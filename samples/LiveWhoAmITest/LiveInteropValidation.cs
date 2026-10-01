using System.Net;
using System.Text.Json.Nodes;
using AAuth.Headers;

namespace LiveWhoAmITest;

public static class LiveInteropValidation
{
    public static bool IsSignatureChallenge(HttpStatusCode status, IEnumerable<string> acceptSignatureValues)
        => status == HttpStatusCode.Unauthorized
            && acceptSignatureValues.Any(value => value.Split(',', StringSplitOptions.TrimEntries).Contains("jwt", StringComparer.OrdinalIgnoreCase));

    public static bool IsAgentIdentityResponse(HttpStatusCode status, string body,
        string expectedIssuer, string expectedSubject, string expectedPersonServer)
        => status == HttpStatusCode.OK
            && ParseObject(body) is { } json
            && StringValue(json, "iss") == expectedIssuer
            && StringValue(json, "sub") == expectedSubject
            && StringValue(json, "ps") == expectedPersonServer;

    // Draft-11: a resource answers a scoped request carrying only an agent token
    // with requirement=person-token; the resource token follows a person token.
    public static bool IsPersonTokenChallenge(HttpStatusCode status,
        AAuthRequirementHeader.ParsedRequirement? requirement)
        => status == HttpStatusCode.Unauthorized
            && requirement?.Requirement == AAuthRequirementHeader.PersonTokenRequirement;

    public static bool IsAuthorizedIdentityResponse(HttpStatusCode status, string body)
        => status == HttpStatusCode.OK
            && ParseObject(body) is { } json
            && !string.IsNullOrWhiteSpace(StringValue(json, "iss"))
            && !string.IsNullOrWhiteSpace(StringValue(json, "sub"));

    private static JsonObject? ParseObject(string body)
    {
        try { return JsonNode.Parse(body) as JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static string? StringValue(JsonObject json, string name)
        => json[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
}
