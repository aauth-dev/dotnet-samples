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
/// parameters. The current implementation covers only the <c>jwt</c> scheme
/// used by agent and auth tokens: <c>Signature-Key: sig=jwt;jwt="eyJ..."</c>.
/// </remarks>
public static class SignatureKeyHeader
{
    /// <summary>The HTTP header name.</summary>
    public const string Name = "Signature-Key";

    /// <summary>Build a <c>Signature-Key</c> header value with the <c>jkt-jwt</c> scheme.</summary>
    /// <param name="jkt">Base64url-encoded JWK thumbprint of the signing key.</param>
    /// <param name="jwt">The JWT (agent/auth token) that binds this thumbprint.</param>
    public static string FormatJktJwt(string jkt, string jwt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jkt);
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        return $"sig=jkt-jwt;jkt=\"{jkt}\";jwt=\"{jwt}\"";
    }

    /// <summary>Build a <c>Signature-Key</c> header value with the <c>hwk</c> scheme (inline public key).</summary>
    /// <param name="jkt">Base64url-encoded JWK thumbprint.</param>
    /// <param name="jwkBase64Url">Base64url-encoded public JWK JSON.</param>
    public static string FormatHwk(string jkt, string jwkBase64Url)
    {
        ArgumentException.ThrowIfNullOrEmpty(jkt);
        ArgumentException.ThrowIfNullOrEmpty(jwkBase64Url);
        return $"sig=hwk;jkt=\"{jkt}\";jwk=\"{jwkBase64Url}\"";
    }

    /// <summary>Build a <c>Signature-Key</c> header value with the <c>jwks_uri</c> scheme.</summary>
    /// <param name="uri">The JWKS URI where the key can be resolved.</param>
    /// <param name="kid">The key id within the JWKS.</param>
    public static string FormatJwksUri(string uri, string kid)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);
        ArgumentException.ThrowIfNullOrEmpty(kid);
        return $"sig=jwks_uri;uri=\"{uri}\";kid=\"{kid}\"";
    }

    /// <summary>Build a <c>Signature-Key</c> header value carrying a JWT.</summary>
    public static string FormatJwt(string jwt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        foreach (var c in jwt)
        {
            // RFC 8941 sf-string excludes control chars and unescaped
            // quote/backslash. Reject defensively so this is safe to use
            // outside HttpClient (which also rejects CR/LF) — e.g. logging,
            // conformance tooling, server-side header reflection.
            if (c < 0x20 || c == 0x7F || c == '"' || c == '\\')
            {
                throw new ArgumentException(
                    "JWT must not contain control characters, quotes, or backslashes.",
                    nameof(jwt));
            }
        }

        return $"sig=jwt;jwt=\"{jwt}\"";
    }

    /// <summary>
    /// Parse a <c>Signature-Key</c> header value and return the JWT if the
    /// scheme is <c>jwt</c>. Returns <c>null</c> for other schemes.
    /// </summary>
    public static string? GetJwt(string headerValue)
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

    // RFC 8941 token = tchar+ where tchar excludes '/' '+' '*' ':' from the
    // RFC 7230 set. We additionally restrict scheme/parameter-name tokens to
    // this tighter grammar so that ':' embedded in an unquoted parameter
    // value (which is not a legal sf-token) is rejected rather than silently
    // accepted as part of the token run.
    private static string ReadToken(string s, ref int idx)
    {
        var start = idx;
        while (idx < s.Length)
        {
            var c = s[idx];
            // RFC 8941 §3.3.4 sf-token chars: ALPHA / DIGIT / "-" / "." / "_"
            // / sub-delims-not-quoted (~ ! # $ & ' ( ) * + , / : ; = ? @)
            // We use the tighter set that suffices for the AAuth schemes and
            // parameter names this header supports today: ALPHA / DIGIT /
            // "-" / "." / "_".
            var ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
                or '-' or '_' or '.';
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
                if (s[idx] == '\\')
                {
                    // RFC 8941 §3.3.3: only \" and \\ are legal escapes in
                    // an sf-string. Any other use of backslash is malformed.
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
