using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3.Model;

/// <summary>A per-call proposal parameter value: inline JSON or digest object.</summary>
[JsonConverter(typeof(R3ParameterJsonConverter))]
public sealed record R3Parameter
{
    public required JsonNode? Json { get; init; }

    public bool IsDigest =>
        TryGetDigestS256(out _);

    public string? S256 => TryGetDigestS256(out var s256) ? s256 : null;

    public void Validate()
    {
        if (Json is not JsonObject value || !value.ContainsKey("s256")) return;
        if (!TryGetDigestS256(out var s256)) throw new InvalidOperationException("R3 digest s256 must be a nonempty string.");
        ValidateS256(s256);
        foreach (var name in new[] { "excerpt", "media_type" })
            if (value.ContainsKey(name) && (value[name] is not JsonValue member || !member.TryGetValue<string>(out _)))
                throw new InvalidOperationException($"R3 digest {name} must be a string when present.");
    }

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

    public R3Parameter DeepClone() => new() { Json = Json?.DeepClone() };

    public static R3Parameter Inline(JsonNode? value) => new() { Json = value?.DeepClone() };

    public static R3Parameter Digest(string s256, string? excerpt = null, string? mediaType = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(s256);
        ValidateS256(s256);
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

    private static void ValidateS256(string s256)
    {
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(s256);
            if (bytes.Length != 32 || Base64UrlEncoder.Encode(bytes) != s256)
                throw new FormatException();
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("R3 digest s256 must be an unpadded base64url SHA-256 digest.", ex);
        }
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
            pair => pair.Value?.DeepClone() ?? throw new ArgumentException("Use R3Parameter.Inline(null) for an explicit JSON null."),
            StringComparer.Ordinal) ?? new Dictionary<string, R3Parameter>(StringComparer.Ordinal);
        _digestParameterBytes = digestParameterBytes?.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.Ordinal) ?? new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (_digestParameterBytes.Keys.Any(JsonParameters.ContainsKey))
            throw new ArgumentException("A parameter cannot be presented as both inline JSON and raw digest bytes.");
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
    public override bool HandleNull => true;

    public override R3Parameter Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        R3Json.ValidateUniqueMembers(document.RootElement);
        var node = JsonNode.Parse(document.RootElement.GetRawText());
        return new R3Parameter { Json = node };
    }

    public override void Write(Utf8JsonWriter writer, R3Parameter value, JsonSerializerOptions options)
    {
        if (value is null) throw new JsonException("Use R3Parameter.Inline(null) for an explicit JSON null.");
        if (value.Json is null) writer.WriteNullValue();
        else value.Json.WriteTo(writer, options);
    }
}
