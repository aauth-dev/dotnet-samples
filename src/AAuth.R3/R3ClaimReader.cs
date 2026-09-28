using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Reads typed R3 claims from a verified JWT payload.</summary>
public static class R3ClaimReader
{
    public sealed record ResourceDocumentClaims(string Uri, string S256)
    {
        public string? Account { get; init; }
    }

    public sealed record AuthTokenClaims(
        string Uri,
        string S256,
        R3Grant Granted,
        R3Grant? PerCall)
    {
        public string? Account { get; init; }
    }

    public static ResourceDocumentClaims? ReadResourceDocument(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        R3AuthClaims.ValidateResourcePair(payload);
        var uri = (string?)payload[R3AuthClaims.UriClaim];
        var s256 = (string?)payload[R3AuthClaims.S256Claim];
        if (uri is null && s256 is null)
        {
            return null;
        }
        return new ResourceDocumentClaims(uri!, s256!) { Account = AAuth.Tokens.AccountBinding.Read(payload) };
    }

    public static AuthTokenClaims ReadAuthToken(JsonObject payload, R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var doc = ReadResourceDocument(payload)
            ?? throw new InvalidOperationException("R3 auth token claims require r3_uri and r3_s256.");
        var granted = ReadGrant(payload[R3AuthClaims.GrantedClaim], schemas)
            ?? throw new InvalidOperationException("R3 auth token claims require r3_granted.");
        if (payload.ContainsKey(R3AuthClaims.PerCallClaim) && payload[R3AuthClaims.PerCallClaim] is null)
            throw new InvalidOperationException("r3_per_call must be an object when present.");
        var perCall = ReadGrant(payload[R3AuthClaims.PerCallClaim], schemas);
        if (perCall is not null && perCall.Vocabulary != granted.Vocabulary)
            throw new InvalidOperationException("R3 granted and per-call vocabularies must match.");
        return new AuthTokenClaims(doc.Uri, doc.S256, granted, perCall) { Account = doc.Account };
    }

    public static R3Grant? ReadGrant(JsonNode? node, R3VocabularySchemas? schemas = null)
    {
        if (node is null)
        {
            return null;
        }
        var json = JsonSerializer.SerializeToElement(node);
        var grant = json.Deserialize<R3Grant>((schemas ?? R3VocabularySchemas.Standard).ReadOptions(json))
            ?? throw new InvalidOperationException("R3 grant claim is not an object.");
        grant.Validate(allowEmpty: true, schemas);
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
