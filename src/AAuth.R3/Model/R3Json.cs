using System.Text.Json;
using System.Text.Json.Serialization;

namespace AAuth.R3.Model;

public static class R3Json
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    internal static JsonSerializerOptions OptionsOrDefault(JsonSerializerOptions? options) => options ?? Options;

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
