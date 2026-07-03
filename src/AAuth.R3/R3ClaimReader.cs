using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Reads typed R3 claims from a verified JWT payload.</summary>
public static class R3ClaimReader
{
    public sealed record ResourceDocumentClaims(string Uri, string S256);

    public sealed record AuthTokenClaims(
        string Uri,
        string S256,
        R3Grant Granted,
        R3Grant? Conditional);

    public static ResourceDocumentClaims? ReadResourceDocument(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var uri = (string?)payload[R3AuthClaims.UriClaim];
        var s256 = (string?)payload[R3AuthClaims.S256Claim];
        if (uri is null && s256 is null)
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(uri) || string.IsNullOrWhiteSpace(s256))
        {
            throw new InvalidOperationException("r3_uri and r3_s256 must be present together.");
        }
        return new ResourceDocumentClaims(uri, s256);
    }

    public static AuthTokenClaims ReadAuthToken(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var doc = ReadResourceDocument(payload)
            ?? throw new InvalidOperationException("R3 auth token claims require r3_uri and r3_s256.");
        var granted = ReadGrant(payload[R3AuthClaims.GrantedClaim])
            ?? throw new InvalidOperationException("R3 auth token claims require r3_granted.");
        var conditional = ReadGrant(payload[R3AuthClaims.ConditionalClaim]);
        return new AuthTokenClaims(doc.Uri, doc.S256, granted, conditional);
    }

    public static R3Grant? ReadGrant(JsonNode? node)
    {
        if (node is null)
        {
            return null;
        }
        var grant = node.Deserialize<R3Grant>(R3Json.Options)
            ?? throw new InvalidOperationException("R3 grant claim is not an object.");
        grant.Validate(allowEmpty: true);
        return grant;
    }
}

internal static class R3ClaimJson
{
    public static JsonObject GrantToJson(R3Grant grant)
    {
        var node = JsonSerializer.SerializeToNode(grant, R3Json.Options) as JsonObject
            ?? throw new InvalidOperationException("R3 grant did not serialize to an object.");
        return node;
    }
}
