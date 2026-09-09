using System.Globalization;
using StructuredFieldValues;
using AAuth.Errors;

namespace AAuth.HttpSig;

internal static class StructuredFields
{
    public static IReadOnlyDictionary<string, ParsedItem> Dictionary(string wire)
    {
        if (SfvParser.ParseDictionary(wire, out var members) is not null)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidRequest, "Malformed structured-field dictionary.");
        var count = string.IsNullOrWhiteSpace(wire) ? 0 : 1;
        var quoted = false;
        var escaped = false;
        var depth = 0;
        foreach (var character in wire)
        {
            if (escaped) { escaped = false; continue; }
            if (quoted && character == '\\') { escaped = true; continue; }
            if (character == '"') { quoted = !quoted; continue; }
            if (quoted) continue;
            if (character == '(') depth++;
            if (character == ')') depth--;
            if (character == ',' && depth == 0) count++;
        }
        if (count != members.Count)
            throw new AAuthVerificationException(SignatureErrorCode.InvalidRequest, "Duplicate signature dictionary labels.");
        return members;
    }

    public static ParsedItem Member(string wire, string label)
    {
        if (!Dictionary(wire).TryGetValue(label, out var member))
            throw new AAuthVerificationException(SignatureErrorCode.InvalidRequest, $"Missing signature label '{label}'.");
        return member;
    }

    public static string String(string value)
    {
        if (value.Any(character => character < 0x20 || character > 0x7e))
            throw new ArgumentException("Structured strings require printable ASCII.", nameof(value));
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    public static string Item(ParsedItem item) => Bare(item.Value) + Parameters(item.Parameters);

    public static string Parameters(IReadOnlyDictionary<string, object> parameters) =>
        string.Concat(parameters.Select(parameter => ";" + parameter.Key
            + (parameter.Value is true ? "" : "=" + Bare(parameter.Value))));

    public static string Bare(object value) => value switch
    {
        string text => String(text),
        Token token => (string)token,
        long integer => integer.ToString(CultureInfo.InvariantCulture),
        double number => number.ToString("0.0##", CultureInfo.InvariantCulture),
        bool boolean => boolean ? "?1" : "?0",
        ReadOnlyMemory<byte> bytes => ":" + Convert.ToBase64String(bytes.Span) + ":",
        IReadOnlyList<ParsedItem> items => "(" + string.Join(" ", items.Select(Item)) + ")",
        _ => throw new AAuthVerificationException(SignatureErrorCode.InvalidRequest, "Unsupported structured-field value type."),
    };

    public static string RequiredString(IReadOnlyDictionary<string, object> parameters, string name)
    {
        if (parameters.TryGetValue(name, out var value) && value is string text && text.Length > 0)
            return text;
        throw new AAuthVerificationException(SignatureErrorCode.InvalidKey, $"'{name}' must be a nonempty structured string.");
    }
}