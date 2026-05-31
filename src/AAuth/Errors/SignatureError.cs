namespace AAuth.Errors;

/// <summary>
/// Error codes for the <c>Signature-Error</c> header per §Verification (Server).
/// Each code maps to a specific verification failure condition.
/// </summary>
public enum SignatureErrorCode
{
    /// <summary>Missing Signature, Signature-Input, or Signature-Key headers.</summary>
    InvalidRequest,

    /// <summary>Covered components do not match the required set or required additional components are missing.</summary>
    InvalidInput,

    /// <summary>The <c>created</c> parameter is outside the server's signature validity window, or signature verification failed.</summary>
    InvalidSignature,

    /// <summary>The signing algorithm is not supported.</summary>
    UnsupportedAlgorithm,

    /// <summary>The key from Signature-Key cannot be parsed.</summary>
    InvalidKey,

    /// <summary>Key referenced by <c>jwks_uri</c> scheme not found.</summary>
    UnknownKey,

    /// <summary>JWT in Signature-Key fails verification (wrong signature, missing claims).</summary>
    InvalidJwt,

    /// <summary>JWT in Signature-Key has expired.</summary>
    ExpiredJwt,
}

/// <summary>
/// Formats and parses the <c>Signature-Error</c> header defined in
/// draft-hardt-httpbis-signature-key.
/// </summary>
public static class SignatureError
{
    /// <summary>The HTTP header name.</summary>
    public const string HeaderName = "Signature-Error";

    /// <summary>Convert an error code to its wire format string.</summary>
    public static string ToHeaderValue(SignatureErrorCode code) => code switch
    {
        SignatureErrorCode.InvalidRequest => "invalid_request",
        SignatureErrorCode.InvalidInput => "invalid_input",
        SignatureErrorCode.InvalidSignature => "invalid_signature",
        SignatureErrorCode.UnsupportedAlgorithm => "unsupported_algorithm",
        SignatureErrorCode.InvalidKey => "invalid_key",
        SignatureErrorCode.UnknownKey => "unknown_key",
        SignatureErrorCode.InvalidJwt => "invalid_jwt",
        SignatureErrorCode.ExpiredJwt => "expired_jwt",
        _ => "invalid_request",
    };

    /// <summary>Format a Signature-Error header value with optional parameters.</summary>
    /// <param name="code">The error code.</param>
    /// <param name="requiredInput">Required covered components (for <c>invalid_input</c>).</param>
    /// <param name="supportedAlgorithms">Supported algorithms (for <c>unsupported_algorithm</c>).</param>
    public static string Format(SignatureErrorCode code, string[]? requiredInput = null, string[]? supportedAlgorithms = null)
    {
        var value = ToHeaderValue(code);
        if (requiredInput is { Length: > 0 } && code == SignatureErrorCode.InvalidInput)
        {
            value += "; required_input=\"" + string.Join(" ", requiredInput) + "\"";
        }
        if (supportedAlgorithms is { Length: > 0 } && code == SignatureErrorCode.UnsupportedAlgorithm)
        {
            value += "; supported_algorithms=\"" + string.Join(" ", supportedAlgorithms) + "\"";
        }
        return value;
    }

    /// <summary>Try to parse a Signature-Error header value to a code.</summary>
    public static bool TryParse(string? headerValue, out SignatureErrorCode code)
    {
        code = default;
        if (string.IsNullOrWhiteSpace(headerValue))
            return false;

        // The header value may contain parameters after `;`
        var semicolonIdx = headerValue.IndexOf(';');
        var codeStr = semicolonIdx >= 0
            ? headerValue[..semicolonIdx].Trim()
            : headerValue.Trim();

        code = codeStr switch
        {
            "invalid_request" => SignatureErrorCode.InvalidRequest,
            "invalid_input" => SignatureErrorCode.InvalidInput,
            "invalid_signature" => SignatureErrorCode.InvalidSignature,
            "unsupported_algorithm" => SignatureErrorCode.UnsupportedAlgorithm,
            "invalid_key" => SignatureErrorCode.InvalidKey,
            "unknown_key" => SignatureErrorCode.UnknownKey,
            "invalid_jwt" => SignatureErrorCode.InvalidJwt,
            "expired_jwt" => SignatureErrorCode.ExpiredJwt,
            _ => default,
        };
        return codeStr is "invalid_request" or "invalid_input" or "invalid_signature"
            or "unsupported_algorithm" or "invalid_key" or "unknown_key"
            or "invalid_jwt" or "expired_jwt";
    }

    /// <summary>
    /// Extract the <c>required_input</c> covered components from a
    /// <c>Signature-Error: invalid_input; required_input="..."</c> header
    /// value. Returns the space-separated component identifiers, or an empty
    /// array when the parameter is absent or malformed.
    /// </summary>
    public static string[] ParseRequiredInput(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            return System.Array.Empty<string>();

        const string marker = "required_input";

        // The header is a list of ';'-separated parameters
        // (e.g. invalid_input; required_input="..."). Match the parameter whose
        // name is exactly "required_input" so tokens like "x-required_input" do
        // not falsely match.
        foreach (var segment in headerValue.Split(';'))
        {
            var eq = segment.IndexOf('=');
            if (eq < 0)
                continue;

            var name = segment[..eq].Trim();
            if (!string.Equals(name, marker, System.StringComparison.Ordinal))
                continue;

            var value = segment[(eq + 1)..].Trim();
            var firstQuote = value.IndexOf('"');
            if (firstQuote < 0)
                return System.Array.Empty<string>();

            var secondQuote = value.IndexOf('"', firstQuote + 1);
            if (secondQuote < 0)
                return System.Array.Empty<string>();

            var inner = value[(firstQuote + 1)..secondQuote];
            return inner.Split(' ', System.StringSplitOptions.RemoveEmptyEntries
                | System.StringSplitOptions.TrimEntries);
        }

        return System.Array.Empty<string>();
    }
}
