using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Composes R3 metadata fields into resource metadata documents.</summary>
public static class R3Metadata
{
    public const string VocabulariesProperty = "r3_vocabularies";

    public static JsonObject AddVocabularies(JsonObject metadata, IReadOnlyDictionary<string, string> vocabularies)
    {
        ArgumentNullException.ThrowIfNull(vocabularies);
        return AddVocabularies(metadata, vocabularies.ToDictionary(entry => entry.Key,
            entry => (JsonNode?)JsonValue.Create(entry.Value), StringComparer.Ordinal));
    }

    public static JsonObject AddVocabularies(JsonObject metadata, IReadOnlyDictionary<string, JsonNode?> vocabularies,
        R3VocabularySchemas? schemas = null)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(vocabularies);
        var values = new JsonObject();
        foreach (var (vocabulary, discoveryEndpoint) in vocabularies)
        {
            (schemas ?? R3VocabularySchemas.Standard).ValidateVocabulary(vocabulary);
            ValidateEndpoint(discoveryEndpoint);
            values[vocabulary] = discoveryEndpoint!.DeepClone();
        }
        metadata[VocabulariesProperty] = values;
        return metadata;
    }

    public static void ValidateOperations(R3Operations request, JsonObject metadata,
        IEnumerable<R3OperationIdentity> authoritativeOperations, R3VocabularySchemas? schemas = null)
    {
        request.Validate(schemas);
        if (metadata[VocabulariesProperty] is not JsonObject vocabularies || !vocabularies.ContainsKey(request.Vocabulary))
            throw new InvalidOperationException("Requested vocabulary is not advertised by this resource.");
        AddVocabularies(new JsonObject(), vocabularies.ToDictionary(entry => entry.Key, entry => entry.Value), schemas);
        R3OperationValidation.ValidateGrant(request.ToGrant(), authoritativeOperations, schemas);
    }

    private static void ValidateEndpoint(JsonNode? node)
    {
        if (node is not JsonValue value || !value.TryGetValue<string>(out var endpoint) ||
            string.IsNullOrWhiteSpace(endpoint) || endpoint.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidOperationException("R3 discovery endpoint must be an absolute HTTP(S) URL.");
    }

    public static JsonObject CreateResourceMetadata(
        string issuer,
        string jwksUri,
        string authorizationEndpoint,
        IReadOnlyDictionary<string, string>? vocabularies = null)
    {
        var trimmedIssuer = issuer.TrimEnd('/');
        var metadata = new JsonObject
        {
            ["issuer"] = trimmedIssuer,
            ["jwks_uri"] = jwksUri,
            ["authorization_endpoint"] = authorizationEndpoint,
        };
        return AddVocabularies(metadata, vocabularies ?? new Dictionary<string, string>
        {
            [Vocabulary.Mcp] = $"{trimmedIssuer}/mcp",
        });
    }
}
