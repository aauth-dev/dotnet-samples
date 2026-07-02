using System.Diagnostics.CodeAnalysis;
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
        TryGetDigestS256(out _);

    public string? S256 => TryGetDigestS256(out var s256) ? s256 : null;

    public bool TryGetDigestS256([NotNullWhen(true)] out string? s256)
    {
        if (Json is JsonObject obj
            && obj["s256"] is JsonValue value
            && value.TryGetValue<string>(out var candidate)
            && !string.IsNullOrWhiteSpace(candidate))
        {
            s256 = candidate;
            return true;
        }

        s256 = null;
        return false;
    }

    public R3Parameter DeepClone() => new() { Json = Json.DeepClone() };

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

/// <summary>Parameters presented on retry: inline JSON values plus raw bytes for digest-backed values.</summary>
public sealed class R3PresentedParameters
{
    private readonly Dictionary<string, byte[]> _digestParameterBytes;

    public R3PresentedParameters(
        IReadOnlyDictionary<string, R3Parameter>? jsonParameters = null,
        IReadOnlyDictionary<string, byte[]>? digestParameterBytes = null)
    {
        JsonParameters = jsonParameters?.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.DeepClone(),
            StringComparer.Ordinal) ?? new Dictionary<string, R3Parameter>(StringComparer.Ordinal);
        _digestParameterBytes = digestParameterBytes?.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.Ordinal) ?? new Dictionary<string, byte[]>(StringComparer.Ordinal);
    }

    public IReadOnlyDictionary<string, R3Parameter> JsonParameters { get; }

    public IReadOnlyCollection<string> DigestParameterNames => _digestParameterBytes.Keys;

    public bool TryGetDigestParameterBytes(string name, out ReadOnlyMemory<byte> bytes)
    {
        if (_digestParameterBytes.TryGetValue(name, out var value))
        {
            bytes = value;
            return true;
        }

        bytes = default;
        return false;
    }

    public static R3PresentedParameters FromJsonParameters(IReadOnlyDictionary<string, R3Parameter> parameters) =>
        new(parameters);
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
