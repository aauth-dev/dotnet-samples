using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>An MCP operation in R3 v02 shape: <c>{ "tool": "..." }</c>.</summary>
public sealed record McpOperation
{
    [JsonPropertyName("tool")]
    [JsonPropertyOrder(1)]
    public required string Tool { get; init; }

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Tool))
        {
            throw new InvalidOperationException("MCP operation tool must be set.");
        }
    }
}
