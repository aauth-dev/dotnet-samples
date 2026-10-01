using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>
/// A vocabulary-specific operation, including qualifiers (such as a WSDL service) and optional members.
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

    public string? Service { get; init; }
    public string? Type { get; init; }
    public string? Action { get; init; }
    public IReadOnlyList<string>? Methods { get; init; }
    public IReadOnlyDictionary<string, JsonElement>? Extensions { get; init; }

    /// <summary>An MCP operation (<c>{ "tool": … }</c>).</summary>
    public static R3Operation Mcp(string tool) => new() { Field = McpField, Id = tool };

    /// <summary>An OpenAPI operation (<c>{ "operationId": … }</c>).</summary>
    public static R3Operation OpenApi(string operationId) => new() { Field = OpenApiField, Id = operationId };

    public static R3Operation Grpc(string method) => new() { Field = "method", Id = method };
    public static R3Operation GraphQl(string operation, string type) => new() { Field = "operation", Id = operation, Type = type };
    public static R3Operation AsyncApi(string operationId, string? action = null) => OpenApi(operationId) with { Action = action };
    public static R3Operation Wsdl(string operation, string? service = null) => new() { Field = "operation", Id = operation, Service = service };
    public static R3Operation OData(string operation, params string[] methods) =>
        new() { Field = "operation", Id = operation, Methods = methods.Length == 0 ? null : methods };

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
        if (Service is not null && string.IsNullOrWhiteSpace(Service) ||
            Type is not null && Type is not ("query" or "mutation" or "subscription") ||
            Action is not null && Action is not ("send" or "receive") ||
            Methods is not null && (Methods.Count == 0 || Methods.Any(method =>
                string.IsNullOrWhiteSpace(method) || method.Any(character => !char.IsAsciiLetterUpper(character))) ||
                Methods.Distinct(StringComparer.Ordinal).Count() != Methods.Count))
            throw new InvalidOperationException("R3 operation contains invalid optional members.");
        if (Extensions?.Keys.Any(member => member == Field ||
            member == "service" && Service is not null || member == "type" && Type is not null ||
            member == "action" && Action is not null || member == "methods" && Methods is not null) == true)
            throw new InvalidOperationException("R3 extension members must not duplicate operation members.");
    }
}

/// <summary>Serializes the vocabulary-specific operation wire members.</summary>
public sealed class R3OperationConverter : JsonConverter<R3Operation>
{
    private readonly string? _identifierMember;

    public R3OperationConverter() { }

    public R3OperationConverter(string identifierMember)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifierMember);
        _identifierMember = identifierMember;
    }

    public override R3Operation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("R3 operation must be a JSON object.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
            if (!members.TryAdd(property.Name, property.Value.Clone()))
                throw new JsonException("Duplicate R3 operation member.");
        var fields = members.Keys.Where(member => member is "tool" or "operationId" or "method" or "operation").ToArray();
        var field = _identifierMember ?? (fields.Length == 1 ? fields[0] : null);
        if (field is null) throw new JsonException("R3 operation requires an unambiguous identifier or explicit vocabulary schema.");
        string? TakeString(string name, bool required = false)
        {
            if (!members.Remove(name, out var value))
            {
                if (required) throw new JsonException($"Missing R3 member '{name}'.");
                return null;
            }
            if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
                throw new JsonException($"R3 member '{name}' must be a nonempty string.");
            return value.GetString();
        }
        var id = TakeString(field, true)!;
        if (_identifierMember is not null)
            return new R3Operation { Field = field, Id = id, Extensions = members.Count == 0 ? null : members };
        var service = TakeString("service");
        var type = TakeString("type");
        var action = TakeString("action");
        string[]? methods = null;
        if (members.Remove("methods", out var methodsJson))
        {
            if (methodsJson.ValueKind != JsonValueKind.Array || methodsJson.EnumerateArray().Any(value => value.ValueKind != JsonValueKind.String))
                throw new JsonException("R3 methods must be an array of strings.");
            methods = methodsJson.EnumerateArray().Select(value => value.GetString()!).ToArray();
        }
        var operation = new R3Operation
        {
            Field = field, Id = id, Service = service, Type = type, Action = action, Methods = methods,
            Extensions = members.Count == 0 ? null : members,
        };
        try { operation.Validate(); }
        catch (InvalidOperationException exception) { throw new JsonException(exception.Message, exception); }
        return operation;
    }

    public override void Write(Utf8JsonWriter writer, R3Operation value, JsonSerializerOptions options)
    {
        value.Validate();
        writer.WriteStartObject();
        writer.WriteString(value.Field, value.Id);
        if (value.Service is not null) writer.WriteString("service", value.Service);
        if (value.Type is not null) writer.WriteString("type", value.Type);
        if (value.Action is not null) writer.WriteString("action", value.Action);
        if (value.Methods is not null)
        {
            writer.WritePropertyName("methods");
            JsonSerializer.Serialize(writer, value.Methods, options);
        }
        if (value.Extensions is not null)
            foreach (var member in value.Extensions.OrderBy(member => member.Key, StringComparer.Ordinal))
            {
                writer.WritePropertyName(member.Key);
                member.Value.WriteTo(writer);
            }
        writer.WriteEndObject();
    }
}
