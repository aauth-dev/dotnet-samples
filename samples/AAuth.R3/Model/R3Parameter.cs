using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

/// <summary>A per-call proposal parameter value: inline JSON or digest object.</summary>
[JsonConverter(typeof(R3ParameterJsonConverter))]
public sealed record R3Parameter
{
    public required JsonNode Json { get; init; }

    public bool IsDigest =>
        Json is JsonObject obj
        && obj["s256"] is JsonValue value
        && value.TryGetValue<string>(out var s256)
        && !string.IsNullOrWhiteSpace(s256);

    public string? S256 => IsDigest ? (string?)Json["s256"] : null;

    public static R3Parameter Inline(JsonNode value) => new() { Json = value.DeepClone() };

    public static R3Parameter Digest(string s256, string? excerpt = null, string? mediaType = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        var obj = new JsonObject { ["s256"] = s256 };
        if (!string.IsNullOrWhiteSpace(excerpt))
        {
            obj["excerpt"] = excerpt;
        }
        if (!string.IsNullOrWhiteSpace(mediaType))
        {
            obj["media_type"] = mediaType;
        }
        return new R3Parameter { Json = obj };
    }
}

internal sealed class R3ParameterJsonConverter : JsonConverter<R3Parameter>
{
    public override R3Parameter? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var node = JsonNode.Parse(ref reader)
            ?? throw new JsonException("R3 parameter value cannot be null.");
        return new R3Parameter { Json = node };
    }

    public override void Write(Utf8JsonWriter writer, R3Parameter value, JsonSerializerOptions options)
    {
        value.Json.WriteTo(writer, options);
    }
}
