using System;

namespace AAuth.Headers;

/// <summary>
/// Formats, parses, and validates the AAuth opaque access credential carried in
/// the <c>AAuth-Access</c> response header and replayed in the
/// <c>Authorization: AAuth &lt;token68&gt;</c> request credential
/// (AAuth protocol §AAuth-Access Response Header).
/// </summary>
/// <remarks>
/// The value is an RFC 9110 §11.2 <c>token68</c>:
/// <c>1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="</c>. Per the
/// AAuth spec, recipients MUST reject empty values, values containing embedded
/// whitespace or control characters, and messages carrying more than one
/// credential. Because none of whitespace, controls, or a second credential are
/// valid <c>token68</c> characters, a single-string value that contains any of
/// them fails <see cref="IsValidToken68"/>; the "more than one credential across
/// repeated header lines" check is enforced by the consuming middleware/handler,
/// which rejects when more than one header value is present.
/// </remarks>
public static class AAuthAccessHeader
{
    /// <summary>The HTTP response header name (<c>AAuth-Access</c>).</summary>
    public const string Name = AAuthConstants.Headers.AAuthAccess;

    /// <summary>The <c>Authorization</c> credential scheme (matched case-insensitively).</summary>
    public const string AuthorizationScheme = "AAuth";

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="value"/> is a valid
    /// RFC 9110 §11.2 <c>token68</c>: at least one base character followed by
    /// zero or more <c>'='</c> padding characters, with nothing else.
    /// </summary>
    public static bool IsValidToken68(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var i = 0;
        var baseChars = 0;
        while (i < value.Length && IsBase68(value[i]))
        {
            i++;
            baseChars++;
        }

        // token68 requires at least one base character before any padding.
        if (baseChars == 0)
        {
            return false;
        }

        // Only '=' padding may follow, and only at the end.
        while (i < value.Length && value[i] == '=')
        {
            i++;
        }

        return i == value.Length;
    }

    /// <summary>
    /// Validate a <c>token68</c>, returning it unchanged, or throwing
    /// <see cref="FormatException"/> if it is empty or contains whitespace,
    /// control characters, or any non-<c>token68</c> character.
    /// </summary>
    public static string ValidateToken68(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsValidToken68(value))
        {
            throw new FormatException(
                "Value is not a valid RFC 9110 token68 (empty, whitespace, control character, "
                + "multiple credentials, or illegal character).");
        }

        return value;
    }

    /// <summary>
    /// Format an <c>Authorization: AAuth &lt;token68&gt;</c> credential value.
    /// Validates <paramref name="token68"/> first.
    /// </summary>
    public static string FormatAuthorization(string token68)
        => $"{AuthorizationScheme} {ValidateToken68(token68)}";

    /// <summary>
    /// Format an <c>AAuth-Access</c> response header value (the bare
    /// <c>token68</c>). Validates <paramref name="token68"/> first.
    /// </summary>
    public static string FormatAccess(string token68)
        => ValidateToken68(token68);

    /// <summary>
    /// Try to parse an <c>Authorization: AAuth &lt;token68&gt;</c> request
    /// credential. Surrounding optional whitespace is ignored; the scheme is
    /// matched case-insensitively; the credential MUST be a single
    /// <c>token68</c> (a second credential or embedded whitespace fails).
    /// </summary>
    public static bool TryParseAuthorization(string? headerValue, out string token68)
    {
        token68 = string.Empty;
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        var s = headerValue.Trim();
        var sp = s.IndexOf(' ');
        if (sp <= 0)
        {
            return false;
        }

        var scheme = s[..sp];
        if (!scheme.Equals(AuthorizationScheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Skip the (one or more) spaces separating scheme and credential. Any
        // remaining whitespace or a second credential makes the token invalid.
        var credential = s[(sp + 1)..].TrimStart(' ');
        if (!IsValidToken68(credential))
        {
            return false;
        }

        token68 = credential;
        return true;
    }

    /// <summary>
    /// Parse an <c>Authorization: AAuth &lt;token68&gt;</c> request credential,
    /// throwing <see cref="FormatException"/> if it is malformed.
    /// </summary>
    public static string ParseAuthorization(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);
        if (!TryParseAuthorization(headerValue, out var token68))
        {
            throw new FormatException(
                "Authorization header is not a valid 'AAuth <token68>' credential.");
        }

        return token68;
    }

    /// <summary>
    /// Try to parse an <c>AAuth-Access</c> response header value (the bare
    /// <c>token68</c>). Surrounding optional whitespace is ignored.
    /// </summary>
    public static bool TryParseAccess(string? headerValue, out string token68)
    {
        token68 = string.Empty;
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        var s = headerValue.Trim();
        if (!IsValidToken68(s))
        {
            return false;
        }

        token68 = s;
        return true;
    }

    /// <summary>
    /// Parse an <c>AAuth-Access</c> response header value, throwing
    /// <see cref="FormatException"/> if it is malformed.
    /// </summary>
    public static string ParseAccess(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);
        if (!TryParseAccess(headerValue, out var token68))
        {
            throw new FormatException(
                "AAuth-Access header is not a valid token68 value.");
        }

        return token68;
    }

    private static bool IsBase68(char c)
        => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '-' or '.' or '_' or '~' or '+' or '/';
}
