using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AAuth.Headers;

/// <summary>
/// Formats and parses the <c>AAuth-Requirement</c> response header
/// (AAuth protocol §AAuth-Requirement Header).
/// </summary>
/// <remarks>
/// The header is an RFC 8941 dictionary whose first member identifies the
/// requirement type, with additional members carrying type-specific
/// parameters. The current implementation handles <c>requirement=auth-token</c>
/// (with a <c>resource-token</c> parameter) plus generic parameter parsing
/// for other requirement types (<c>interaction</c>, <c>clarification</c>,
/// <c>claims</c>, <c>approval</c>) so server-side challenge logic and the
/// agent-side challenge handler can both round-trip the values.
/// </remarks>
public static class AAuthRequirementHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "AAuth-Requirement";

    /// <summary>Requirement type: <c>auth-token</c>.</summary>
    public const string AuthTokenRequirement = "auth-token";

    /// <summary>The parameter name carrying the resource token.</summary>
    public const string ResourceTokenParameter = "resource-token";

    /// <summary>Build an <c>auth-token</c> requirement header value.</summary>
    public static string FormatAuthToken(string resourceToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        foreach (var c in resourceToken)
        {
            // Mirror SignatureKeyHeader.FormatJwt — defend against control
            // chars / quotes / backslashes so this is safe in non-HttpClient
            // contexts.
            if (c < 0x20 || c == 0x7F || c == '"' || c == '\\')
            {
                throw new ArgumentException(
                    "Resource token must not contain control characters, quotes, or backslashes.",
                    nameof(resourceToken));
            }
        }

        return $"requirement={AuthTokenRequirement}; {ResourceTokenParameter}=\"{resourceToken}\"";
    }

    /// <summary>Parsed <c>AAuth-Requirement</c> header.</summary>
    /// <param name="Requirement">The requirement type (e.g. <c>auth-token</c>).</param>
    /// <param name="Parameters">All other dictionary parameters by name.</param>
    public sealed record ParsedRequirement(
        string Requirement,
        IReadOnlyDictionary<string, string> Parameters)
    {
        /// <summary>Convenience accessor for <c>resource-token</c>.</summary>
        public string? ResourceToken =>
            Parameters.TryGetValue(ResourceTokenParameter, out var v) ? v : null;
    }

    /// <summary>Parse an <c>AAuth-Requirement</c> header value.</summary>
    public static ParsedRequirement Parse(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);
        var input = headerValue.Trim();

        const string prefix = "requirement=";
        if (!input.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new FormatException("AAuth-Requirement header must start with 'requirement='.");
        }

        int idx = prefix.Length;
        var requirement = ReadToken(input, ref idx);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        while (idx < input.Length)
        {
            if (input[idx] != ';')
            {
                throw new FormatException($"Expected ';' at position {idx}.");
            }
            idx++;
            SkipWs(input, ref idx);
            if (idx >= input.Length) { break; }
            var name = ReadToken(input, ref idx);
            if (idx >= input.Length || input[idx] != '=')
            {
                throw new FormatException($"Expected '=' after parameter '{name}'.");
            }
            idx++;
            var value = ReadParameterValue(input, ref idx);
            parameters[name] = value;
            SkipWs(input, ref idx);
        }

        return new ParsedRequirement(requirement, parameters);
    }

    // The parser below intentionally mirrors `SignatureKeyHeader`'s structure
    // and grammar. The two headers share enough form (sf-dictionary with
    // sf-token keys and sf-string parameter values) that the duplication is
    // small and the alternative — a shared util class — would expose its
    // shape across two otherwise-independent specs. Revisit if a third
    // AAuth header lands.
    private static string ReadToken(string s, ref int idx)
    {
        var start = idx;
        while (idx < s.Length)
        {
            var c = s[idx];
            var ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
                or '-' or '_' or '.';
            if (!ok) { break; }
            idx++;
        }
        if (idx == start)
        {
            throw new FormatException($"Expected token at position {start}.");
        }
        return s[start..idx];
    }

    private static string ReadParameterValue(string s, ref int idx)
    {
        if (idx < s.Length && s[idx] == '"')
        {
            idx++;
            var sb = new StringBuilder();
            while (idx < s.Length && s[idx] != '"')
            {
                if (s[idx] == '\\')
                {
                    if (idx + 1 >= s.Length)
                    {
                        throw new FormatException("Unterminated escape sequence.");
                    }
                    var next = s[idx + 1];
                    if (next != '"' && next != '\\')
                    {
                        throw new FormatException($"Invalid escape '\\{next}' at position {idx}.");
                    }
                    sb.Append(next);
                    idx += 2;
                }
                else
                {
                    sb.Append(s[idx]);
                    idx++;
                }
            }
            if (idx >= s.Length)
            {
                throw new FormatException("Unterminated quoted string.");
            }
            idx++;
            return sb.ToString();
        }
        return ReadToken(s, ref idx);
    }

    private static void SkipWs(string s, ref int idx)
    {
        while (idx < s.Length && (s[idx] == ' ' || s[idx] == '\t'))
        {
            idx++;
        }
    }
}
