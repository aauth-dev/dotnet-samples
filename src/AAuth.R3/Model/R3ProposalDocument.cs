using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>A per-call R3 proposal document bound to concrete call parameters.</summary>
public sealed record R3ProposalDocument
{
    [JsonPropertyName("account")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Account { get; init; }

    [JsonPropertyName("version")]
    [JsonPropertyOrder(1)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; init; }

    [JsonPropertyName("vocabulary")]
    [JsonPropertyOrder(2)]
    public required string Vocabulary { get; init; }

    [JsonPropertyName("operations")]
    [JsonPropertyOrder(3)]
    public required IReadOnlyList<R3Operation> Operations { get; init; }

    [JsonPropertyName("parameters")]
    [JsonPropertyOrder(4)]
    public required IReadOnlyDictionary<string, R3Parameter> Parameters { get; init; }

    [JsonPropertyName("display")]
    [JsonPropertyOrder(5)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public R3Display? Display { get; init; }

    public void Validate(R3VocabularySchemas? schemas = null)
    {
        AAuth.Tokens.AccountBinding.Validate(Account);
        new R3Grant { Vocabulary = Vocabulary, Operations = Operations }.Validate(schemas: schemas);
        if (Operations.Count != 1)
        {
            throw new InvalidOperationException("R3ProposalDocument must contain exactly one operation.");
        }
        if (Parameters is null)
        {
            throw new InvalidOperationException("R3ProposalDocument.parameters is required.");
        }
        foreach (var (name, parameter) in Parameters)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new InvalidOperationException("R3ProposalDocument parameter names must be non-empty.");
            }
            if (parameter is null)
            {
                throw new InvalidOperationException($"R3ProposalDocument parameter '{name}' is null.");
            }
            parameter.Validate();
        }
        Display?.Validate();
    }

    public byte[] ToUtf8Bytes(JsonSerializerOptions? options = null, R3VocabularySchemas? schemas = null)
    {
        Validate(schemas);
        return JsonSerializer.SerializeToUtf8Bytes(this, R3Json.OptionsOrDefault(options));
    }

    public static R3ProposalDocument FromUtf8Bytes(ReadOnlySpan<byte> bytes, JsonSerializerOptions? options = null, R3VocabularySchemas? schemas = null)
    {
        using var json = JsonDocument.Parse(bytes.ToArray());
        R3Json.ValidateUniqueMembers(json.RootElement);
        AAuth.Tokens.AccountBinding.Read(System.Text.Json.Nodes.JsonNode.Parse(bytes) as System.Text.Json.Nodes.JsonObject);
        var doc = json.RootElement.Deserialize<R3ProposalDocument>((schemas ?? R3VocabularySchemas.Standard).ReadOptions(json.RootElement, options))
            ?? throw new InvalidOperationException("R3 proposal JSON did not deserialize to an object.");
        doc.Validate(schemas);
        return doc;
    }
}
