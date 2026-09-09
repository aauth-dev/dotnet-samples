using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

public static class R3Json
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    internal static JsonSerializerOptions OptionsOrDefault(JsonSerializerOptions? options) => options ?? Options;

    internal static void ValidateUniqueMembers(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException("Duplicate R3 JSON member.");
                ValidateUniqueMembers(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) ValidateUniqueMembers(item);
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
        };
        options.Converters.Add(new R3ParameterJsonConverter());
        return options;
    }
}
