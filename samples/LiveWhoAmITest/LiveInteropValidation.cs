using System.Net;
using System.Text.Json.Nodes;
using AAuth.Headers;
using Microsoft.IdentityModel.Tokens;

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

    public static bool IsAuthTokenChallenge(HttpStatusCode status,
        AAuthRequirementHeader.ParsedRequirement? requirement)
        => status == HttpStatusCode.Unauthorized
            && requirement?.Requirement == AAuthRequirementHeader.AuthTokenRequirement
            && IsCompactJws(requirement.ResourceToken);

    public static bool IsAuthorizedIdentityResponse(HttpStatusCode status, string body)
        => status == HttpStatusCode.OK
            && ParseObject(body) is { } json
            && !string.IsNullOrWhiteSpace(StringValue(json, "iss"))
            && !string.IsNullOrWhiteSpace(StringValue(json, "sub"));

    private static bool IsCompactJws(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var segments = value.Split('.');
        if (segments.Length != 3 || segments.Any(segment => segment.Length == 0
            || segment.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))))
            return false;
        try { return segments.All(segment => Base64UrlEncoder.DecodeBytes(segment).Length > 0); }
        catch (FormatException) { return false; }
    }

    private static JsonObject? ParseObject(string body)
    {
        try { return JsonNode.Parse(body) as JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static string? StringValue(JsonObject json, string name)
        => json[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
}
