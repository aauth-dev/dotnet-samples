using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>R3 granted or conditional operations.</summary>
public sealed record R3Grant
{
    [JsonPropertyName("vocabulary")]
    [JsonPropertyOrder(1)]
    public required string Vocabulary { get; init; }

    [JsonPropertyName("operations")]
    [JsonPropertyOrder(2)]
    public required IReadOnlyList<R3Operation> Operations { get; init; }

    public static R3Grant Mcp(params string[] tools) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.Mcp,
        Operations = tools.Select(R3Operation.Mcp).ToArray(),
    };

    public static R3Grant OpenApi(params string[] operationIds) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.OpenApi,
        Operations = operationIds.Select(R3Operation.OpenApi).ToArray(),
    };

    public bool Contains(R3OperationIdentity operation) =>
        Operations.Any(candidate => new R3OperationIdentity(Vocabulary, candidate).Covers(operation));

    public void Validate(bool allowEmpty = false, R3VocabularySchemas? schemas = null)
    {
        (schemas ?? R3VocabularySchemas.Standard).ValidateVocabulary(Vocabulary);
        if (Operations is null || (!allowEmpty && Operations.Count == 0))
        {
            throw new InvalidOperationException("operations must contain at least one operation.");
        }
        foreach (var op in Operations)
        {
            (schemas ?? R3VocabularySchemas.Standard).Validate(Vocabulary, op);
        }
    }
}
