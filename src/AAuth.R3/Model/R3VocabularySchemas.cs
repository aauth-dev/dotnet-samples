using System.Text.Json;
using System.Text.RegularExpressions;

namespace AAuth.R3.Model;

public sealed class R3VocabularySchemas
{
    private readonly IReadOnlyDictionary<string, R3VocabularySchema> _custom;

    public R3VocabularySchemas(IReadOnlyDictionary<string, R3VocabularySchema>? custom = null)
    {
        _custom = new Dictionary<string, R3VocabularySchema>(custom ?? new Dictionary<string, R3VocabularySchema>(), StringComparer.Ordinal);
        foreach (var entry in _custom)
        {
            ValidateUri(entry.Key);
            if (entry.Key.StartsWith("urn:aauth:vocabulary:", StringComparison.Ordinal) || entry.Value is null ||
                string.IsNullOrWhiteSpace(entry.Value.IdentifierMember) || entry.Value.Validate is null)
                throw new ArgumentException("Custom schemas require a third-party URI, explicit identifier member, and validator.", nameof(custom));
        }
    }

    public static R3VocabularySchemas Standard { get; } = new();

    public JsonSerializerOptions CreateJsonOptions(string vocabulary, JsonSerializerOptions? options = null)
    {
        ValidateVocabulary(vocabulary);
        var selected = R3Json.OptionsOrDefault(options);
        if (!_custom.TryGetValue(vocabulary, out var schema)) return selected;
        var configured = new JsonSerializerOptions(selected);
        configured.Converters.Insert(0, new R3OperationConverter(schema.IdentifierMember));
        return configured;
    }

    internal JsonSerializerOptions ReadOptions(JsonElement document, JsonSerializerOptions? options = null)
    {
        if (document.ValueKind != JsonValueKind.Object || !document.TryGetProperty("vocabulary", out var vocabulary) ||
            vocabulary.ValueKind != JsonValueKind.String)
            throw new JsonException("R3 vocabulary must be a string.");
        return CreateJsonOptions(vocabulary.GetString()!, options);
    }

    public static void ValidateUri(string vocabulary)
    {
        if (string.IsNullOrWhiteSpace(vocabulary) || vocabulary.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(vocabulary, UriKind.Absolute, out _))
            throw new InvalidOperationException("R3 vocabulary must be an absolute URI.");
    }

    public void Validate(string vocabulary, R3Operation operation)
    {
        ValidateVocabulary(vocabulary);
        if (operation is null) throw new InvalidOperationException("R3 operation must be an object.");
        operation.Validate();
        if (_custom.TryGetValue(vocabulary, out var schema))
        {
            if (operation.Field != schema.IdentifierMember || !NoQualifiers(operation))
                throw new InvalidOperationException("Custom operations require the declared identifier and extension members.");
            schema.Validate(operation);
            return;
        }
        var valid = vocabulary switch
        {
            Vocabulary.Mcp => operation.Field == "tool" && NoQualifiers(operation),
            Vocabulary.OpenApi => operation.Field == "operationId" && NoQualifiers(operation),
            Vocabulary.OpenApiGateway => operation.Field == "operationId" && operation.Service is not null &&
                operation.Type is null && operation.Action is null && operation.Methods is null,
            Vocabulary.Grpc => operation.Field == "method" && NoQualifiers(operation) &&
                Regex.IsMatch(operation.Id, @"\A(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*\z"),
            Vocabulary.GraphQl => operation.Field == "operation" && operation.Type is not null &&
                operation.Service is null && operation.Action is null && operation.Methods is null &&
                Regex.IsMatch(operation.Id, @"\A[_A-Za-z][_0-9A-Za-z]*\z"),
            Vocabulary.AsyncApi => operation.Field == "operationId" && operation.Service is null &&
                operation.Type is null && operation.Methods is null,
            Vocabulary.Wsdl => operation.Field == "operation" && operation.Type is null &&
                operation.Action is null && operation.Methods is null,
            Vocabulary.OData => operation.Field == "operation" && operation.Service is null &&
                operation.Type is null && operation.Action is null &&
                (!operation.Id.Contains('/') || operation.Methods is null),
            _ => throw new InvalidOperationException($"No R3 schema configured for '{vocabulary}'."),
        };
        if (!valid || operation.Extensions?.Count > 0)
            throw new InvalidOperationException($"Invalid operation shape for '{vocabulary}'.");
    }

    private static bool NoQualifiers(R3Operation operation) => operation.Service is null &&
        operation.Type is null && operation.Action is null && operation.Methods is null;

    public void ValidateVocabulary(string vocabulary)
    {
        ValidateUri(vocabulary);
        if (vocabulary is not (Vocabulary.Mcp or Vocabulary.OpenApi or Vocabulary.OpenApiGateway or
            Vocabulary.Grpc or Vocabulary.GraphQl or Vocabulary.AsyncApi or Vocabulary.Wsdl or Vocabulary.OData) &&
            !_custom.ContainsKey(vocabulary))
            throw new InvalidOperationException($"No R3 schema configured for '{vocabulary}'.");
    }
}

public sealed record R3VocabularySchema(string IdentifierMember, Action<R3Operation> Validate);