using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>An R3 document served verbatim by a resource.</summary>
public sealed record R3Document
{
    [JsonPropertyName("version")]
    [JsonPropertyOrder(1)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; init; }

    [JsonPropertyName("vocabulary")]
    [JsonPropertyOrder(2)]
    public required string Vocabulary { get; init; }

    [JsonPropertyName("operations")]
    [JsonPropertyOrder(3)]
    public required IReadOnlyList<McpOperation> Operations { get; init; }

    [JsonPropertyName("display")]
    [JsonPropertyOrder(4)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public R3Display? Display { get; init; }

    /// <summary>
    /// Operations the resource declares as conditional (per-call approval). The AS
    /// derives the granted-vs-conditional split from this list, so no per-AS config
    /// is required. Omitted from the wire (and the content hash) when null.
    /// </summary>
    [JsonPropertyName("conditional")]
    [JsonPropertyOrder(5)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<McpOperation>? Conditional { get; init; }

    public static R3Document Mcp(IReadOnlyList<McpOperation> operations, R3Display? display = null) => new()
    {
        Version = "v02",
        Vocabulary = global::AAuth.R3.Model.Vocabulary.Mcp,
        Operations = operations,
        Display = display,
    };

    public void Validate()
    {
        new R3Grant { Vocabulary = Vocabulary, Operations = Operations }.Validate();
        Display?.Validate();
    }

    public byte[] ToUtf8Bytes(JsonSerializerOptions? options = null)
    {
        Validate();
        return JsonSerializer.SerializeToUtf8Bytes(this, R3Json.OptionsOrDefault(options));
    }

    public static R3Document FromUtf8Bytes(ReadOnlySpan<byte> bytes, JsonSerializerOptions? options = null)
    {
        var doc = JsonSerializer.Deserialize<R3Document>(bytes, R3Json.OptionsOrDefault(options))
            ?? throw new InvalidOperationException("R3 document JSON did not deserialize to an object.");
        doc.Validate();
        return doc;
    }
}
