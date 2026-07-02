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
    public required IReadOnlyList<McpOperation> Operations { get; init; }

    public static R3Grant Mcp(params string[] tools) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.Mcp,
        Operations = tools.Select(tool => new McpOperation { Tool = tool }).ToArray(),
    };

    public bool ContainsTool(string tool) =>
        string.Equals(Vocabulary, global::AAuth.R3.Model.Vocabulary.Mcp, StringComparison.Ordinal)
        && Operations.Any(op => string.Equals(op.Tool, tool, StringComparison.Ordinal));

    public void Validate(bool allowEmpty = false)
    {
        if (!string.Equals(Vocabulary, global::AAuth.R3.Model.Vocabulary.Mcp, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Only the MCP vocabulary is supported (" + global::AAuth.R3.Model.Vocabulary.Mcp + ").");
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
