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

    public bool Contains(string operationId) =>
        Operations.Any(op => string.Equals(op.Id, operationId, StringComparison.Ordinal));

    public void Validate(bool allowEmpty = false)
    {
        if (string.IsNullOrWhiteSpace(Vocabulary))
        {
            throw new InvalidOperationException("vocabulary must be set.");
        }
        if (Operations is null || (!allowEmpty && Operations.Count == 0))
        {
            throw new InvalidOperationException("operations must contain at least one operation.");
        }
        foreach (var op in Operations)
        {
            op.Validate();
        }
    }
}
