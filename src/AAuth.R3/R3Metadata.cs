using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Composes R3 metadata fields into resource metadata documents.</summary>
public static class R3Metadata
{
    public const string VocabulariesProperty = "r3_vocabularies";

    public static JsonObject AddVocabularies(JsonObject metadata, IReadOnlyDictionary<string, string> vocabularies)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(vocabularies);
        var values = new JsonObject();
        foreach (var (vocabulary, discoveryEndpoint) in vocabularies)
        {
            if (string.IsNullOrWhiteSpace(vocabulary))
            {
                throw new InvalidOperationException("R3 vocabulary values must be non-empty.");
            }
            if (string.IsNullOrWhiteSpace(discoveryEndpoint))
            {
                throw new InvalidOperationException("R3 vocabulary discovery endpoints must be non-empty.");
            }
            values[vocabulary] = discoveryEndpoint;
        }
        metadata[VocabulariesProperty] = values;
        return metadata;
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
