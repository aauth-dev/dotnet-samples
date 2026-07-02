using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>
/// A single R3 operation entry. Operation entries are single-key JSON objects whose
/// member name is vocabulary-specific (MCP <c>tool</c>, OpenAPI <c>operationId</c>,
/// gRPC <c>method</c>, …) and whose value is the operation identifier
/// (r3 §Standard Vocabularies). This type is vocabulary-agnostic: it carries the
/// member name (<see cref="Field"/>) alongside the identifier (<see cref="Id"/>) and
/// serializes back to the exact single-key shape, keeping the document byte-stable
/// for content addressing.
/// </summary>
[JsonConverter(typeof(R3OperationConverter))]
public sealed record R3Operation
{
    /// <summary>Vocabulary member name for MCP operations (<c>tool</c>).</summary>
    public const string McpField = "tool";

    /// <summary>Vocabulary member name for OpenAPI operations (<c>operationId</c>).</summary>
    public const string OpenApiField = "operationId";

    /// <summary>The vocabulary-specific member name (e.g. <c>tool</c>, <c>operationId</c>).</summary>
    public required string Field { get; init; }

    /// <summary>The operation identifier value.</summary>
    public required string Id { get; init; }

    /// <summary>An MCP operation (<c>{ "tool": … }</c>).</summary>
    public static R3Operation Mcp(string tool) => new() { Field = McpField, Id = tool };

    /// <summary>An OpenAPI operation (<c>{ "operationId": … }</c>).</summary>
    public static R3Operation OpenApi(string operationId) => new() { Field = OpenApiField, Id = operationId };

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Field))
        {
            throw new InvalidOperationException("R3 operation member name must be set.");
        }
        if (string.IsNullOrWhiteSpace(Id))
        {
            throw new InvalidOperationException($"R3 operation '{Field}' identifier must be set.");
        }
    }
}

/// <summary>Serializes an <see cref="R3Operation"/> as its single-key <c>{ field: id }</c> object.</summary>
public sealed class R3OperationConverter : JsonConverter<R3Operation>
{
    public override R3Operation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("R3 operation must be a JSON object.");
        }

        string? field = null;
        string? id = null;
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException("R3 operation is malformed.");
            }
            if (field is not null)
            {
                throw new JsonException("R3 operation must contain exactly one member.");
            }
            field = reader.GetString();
            reader.Read();
            if (reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException($"R3 operation member '{field}' must be a string.");
            }
            id = reader.GetString();
        }

        if (string.IsNullOrEmpty(field) || id is null)
        {
            throw new JsonException("R3 operation must contain exactly one string member.");
        }
        return new R3Operation { Field = field, Id = id };
    }

    public override void Write(Utf8JsonWriter writer, R3Operation value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString(value.Field, value.Id);
        writer.WriteEndObject();
    }
}
