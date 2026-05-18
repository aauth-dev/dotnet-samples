using System;
using System.Collections.Generic;
using System.Text;

namespace AAuth.HttpSig;

/// <summary>
/// Formats and parses the <c>Signature-Key</c> header
/// (<a href="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/">draft-hardt-httpbis-signature-key</a>).
/// </summary>
/// <remarks>
/// The header is an RFC 8941 dictionary. AAuth uses the dictionary key
/// <c>sig</c> whose item is a token naming the scheme, with scheme-specific
/// parameters. Phase 1 covers only the <c>jwt</c> scheme used by agent and
/// auth tokens: <c>Signature-Key: sig=jwt;jwt="eyJ..."</c>.
/// </remarks>
public static class SignatureKeyHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "Signature-Key";

    /// <summary>Build a <c>Signature-Key</c> header value carrying a JWT.</summary>
    public static string FormatJwt(string jwt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        if (jwt.IndexOf('"') >= 0 || jwt.IndexOf('\\') >= 0)
        {
            throw new ArgumentException("JWT must not contain quotes or backslashes.", nameof(jwt));
        }

        return $"sig=jwt;jwt=\"{jwt}\"";
    }

    /// <summary>
    /// Parse a <c>Signature-Key</c> header value and return the JWT if the
    /// scheme is <c>jwt</c>. Throws on malformed input. Returns <c>null</c>
    /// for non-<c>jwt</c> schemes (e.g. <c>hwk</c>, <c>jkt-jwt</c>,
    /// <c>jwks_uri</c>) which are out of scope for Phase 1.
    /// </summary>
    public static string? TryGetJwt(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);

        var (scheme, parameters) = Parse(headerValue);
        if (scheme != "jwt")
        {
            return null;
        }

        return parameters.TryGetValue("jwt", out var jwt) ? jwt : null;
    }

    /// <summary>
    /// Parse a <c>Signature-Key</c> header value into its scheme name and
    /// scheme parameters. Whitespace around tokens is tolerated.
    /// </summary>
    public static (string Scheme, IReadOnlyDictionary<string, string> Parameters) Parse(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);

        var input = headerValue.Trim();

        const string keyPrefix = "sig=";
        if (!input.StartsWith(keyPrefix, StringComparison.Ordinal))
        {
            throw new FormatException("Signature-Key header must start with 'sig='.");
        }

        int idx = keyPrefix.Length;
        var scheme = ReadToken(input, ref idx);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        while (idx < input.Length)
        {
            if (input[idx] != ';')
            {
                throw new FormatException($"Expected ';' at position {idx}.");
            }
            idx++;
            SkipWs(input, ref idx);
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

        return (scheme, parameters);
    }

    private static string ReadToken(string s, ref int idx)
    {
        var start = idx;
        while (idx < s.Length)
        {
            var c = s[idx];
            var ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
                or '-' or '_' or '.' or '/' or '+' or '*' or ':';
            if (!ok)
            {
                break;
            }
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
                if (s[idx] == '\\' && idx + 1 < s.Length)
                {
                    sb.Append(s[idx + 1]);
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
