using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

namespace AAuth.Protocol;

internal static class AAuthProtocolInput
{
    private static readonly HashSet<string> PlatformValues = new(StringComparer.Ordinal)
    {
        AAuthConstants.Platforms.Web,
        AAuthConstants.Platforms.Mobile,
        AAuthConstants.Platforms.Desktop,
        AAuthConstants.Platforms.Workload,
        AAuthConstants.Platforms.SelfHosted,
    };

    public static string? ValidatePlatform(string? value, string parameterName)
    {
        if (value is null)
        {
            return null;
        }

        if (!PlatformValues.Contains(value))
        {
            throw new ArgumentException("platform must be a value from the AAuth Platform Value Registry.", parameterName);
        }

        return value;
    }

    public static string? ValidateDevice(string? value, string parameterName)
    {
        if (value is null)
        {
            return null;
        }

        for (var i = 0; i < value.Length; i++)
        {
            if (!char.IsSurrogate(value[i]))
            {
                continue;
            }

            if (i + 1 < value.Length && char.IsSurrogatePair(value[i], value[i + 1]))
            {
                i++;
                continue;
            }

            throw new ArgumentException(
                "device must contain only valid Unicode scalar values.",
                parameterName);
        }

        var runeCount = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            runeCount++;
            if (runeCount > 64)
            {
                throw new ArgumentException("device must be at most 64 Unicode scalar values.", parameterName);
            }

            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse
                or UnicodeCategory.OtherNotAssigned)
            {
                throw new ArgumentException(
                    "device must contain only printable Unicode scalar values.",
                    parameterName);
            }
        }

        if (runeCount == 0)
        {
            throw new ArgumentException("device must not be empty when present.", parameterName);
        }

        return value;
    }

    public static IReadOnlyList<string> ValidateCapabilities(IEnumerable<string> capabilities, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        var result = new List<string>();
        foreach (var capability in capabilities)
        {
            result.Add(ValidateCapability(capability, parameterName));
        }

        return result.ToArray();
    }

    public static string ValidateCapability(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("capability values must be non-empty HTTP tokens.", parameterName);
        }

        var trimmed = value.Trim();
        if (!IsHttpToken(trimmed))
        {
            throw new ArgumentException("capability values must be valid HTTP tokens.", parameterName);
        }

        return trimmed;
    }

    public static IReadOnlyList<string>? ReadCapabilities(JsonObject body, out bool present)
    {
        ArgumentNullException.ThrowIfNull(body);
        present = body.ContainsKey("capabilities");
        if (!present)
        {
            return null;
        }

        if (body["capabilities"] is not JsonArray array)
        {
            throw new ArgumentException("capabilities must be an array of HTTP token strings.", "capabilities");
        }

        var values = new List<string>(array.Count);
        foreach (var node in array)
        {
            if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
            {
                throw new ArgumentException("capabilities entries must be strings.", "capabilities");
            }

            values.Add(ValidateCapability(text, "capabilities"));
        }

        return values.ToArray();
    }

    private static bool IsHttpToken(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        return value.All(static ch =>
            ch is >= '0' and <= '9'
                or >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or '!' or '#' or '$' or '%' or '&' or '\'' or '*'
                or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
    }
}
