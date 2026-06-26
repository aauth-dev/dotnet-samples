using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3;

/// <summary>Composes R3 metadata fields into resource metadata documents.</summary>
public static class R3Metadata
{
    public const string VocabulariesProperty = "r3_vocabularies";

    public static JsonObject AddVocabularies(JsonObject metadata, params string[] vocabularies)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var values = vocabularies.Length == 0 ? [Vocabulary.Mcp] : vocabularies;
        var array = new JsonArray();
        foreach (var vocabulary in values.Distinct(StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(vocabulary))
            {
                throw new InvalidOperationException("R3 vocabulary values must be non-empty.");
            }
            array.Add(vocabulary);
        }
        metadata[VocabulariesProperty] = array;
        return metadata;
    }

    public static JsonObject CreateResourceMetadata(
        string issuer,
        string jwksUri,
        string authorizationEndpoint,
        IEnumerable<string>? vocabularies = null)
    {
        var metadata = new JsonObject
        {
            ["issuer"] = issuer,
            ["jwks_uri"] = jwksUri,
            ["authorization_endpoint"] = authorizationEndpoint,
        };
        return AddVocabularies(metadata, (vocabularies ?? [Vocabulary.Mcp]).ToArray());
    }
}
