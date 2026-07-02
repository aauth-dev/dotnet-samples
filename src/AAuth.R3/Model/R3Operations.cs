using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>The <c>r3_operations</c> request object.</summary>
public sealed record R3Operations
{
    [JsonPropertyName("vocabulary")]
    [JsonPropertyOrder(1)]
    public required string Vocabulary { get; init; }

    [JsonPropertyName("operations")]
    [JsonPropertyOrder(2)]
    public required IReadOnlyList<McpOperation> Operations { get; init; }

    public static R3Operations Mcp(params string[] tools) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.Mcp,
        Operations = tools.Select(tool => new McpOperation { Tool = tool }).ToArray(),
    };

    public R3Grant ToGrant() => new() { Vocabulary = Vocabulary, Operations = Operations };

    public void Validate() => ToGrant().Validate();
}
