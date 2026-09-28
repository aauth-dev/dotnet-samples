using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>An R3 document served verbatim by a resource.</summary>
public sealed record R3Document
{
    [JsonPropertyName("account")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Account { get; init; }

    [JsonPropertyName("vocabulary")]
    [JsonPropertyOrder(2)]
    public required string Vocabulary { get; init; }

    [JsonPropertyName("operations")]
    [JsonPropertyOrder(3)]
    public required IReadOnlyList<R3Operation> Operations { get; init; }

    [JsonPropertyName("display")]
    [JsonPropertyOrder(4)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public R3Display? Display { get; init; }

    public static R3Document Mcp(IReadOnlyList<R3Operation> operations, R3Display? display = null) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.Mcp,
        Operations = operations,
        Display = display,
    };

    public static R3Document OpenApi(IReadOnlyList<R3Operation> operations, R3Display? display = null) => new()
    {
        Vocabulary = global::AAuth.R3.Model.Vocabulary.OpenApi,
        Operations = operations,
        Display = display,
    };

    public void Validate(R3VocabularySchemas? schemas = null)
    {
        AAuth.Tokens.AccountBinding.Validate(Account);
        new R3Grant { Vocabulary = Vocabulary, Operations = Operations }.Validate(schemas: schemas);
        Display?.Validate();
    }

    public byte[] ToUtf8Bytes(JsonSerializerOptions? options = null, R3VocabularySchemas? schemas = null)
    {
        Validate(schemas);
        return JsonSerializer.SerializeToUtf8Bytes(this, R3Json.OptionsOrDefault(options));
    }

    public static R3Document FromUtf8Bytes(ReadOnlySpan<byte> bytes, JsonSerializerOptions? options = null, R3VocabularySchemas? schemas = null)
    {
        AAuth.Tokens.AccountBinding.Read(System.Text.Json.Nodes.JsonNode.Parse(bytes) as System.Text.Json.Nodes.JsonObject);
        using var json = JsonDocument.Parse(bytes.ToArray());
        var doc = json.RootElement.Deserialize<R3Document>((schemas ?? R3VocabularySchemas.Standard).ReadOptions(json.RootElement, options))
            ?? throw new InvalidOperationException("R3 document JSON did not deserialize to an object.");
        doc.Validate(schemas);
        return doc;
    }
}
