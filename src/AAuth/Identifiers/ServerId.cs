using System;
using System.Globalization;

namespace AAuth.Identifiers;

/// <summary>
/// Validates and normalises an AAuth server identifier per §Server Identifiers.
/// Rules: MUST use https, host-only (no port, path, query, or fragment),
/// no trailing slash, lowercase, IDN → ACE form. Loopback (localhost,
/// 127.0.0.1, ::1) may include port for dev use.
/// </summary>
public readonly struct ServerId : IEquatable<ServerId>
{
    private readonly string _value;

    private ServerId(string value) => _value = value;

    /// <summary>The normalised identifier value.</summary>
    public string Value => _value;

    /// <summary>Parse and validate a server identifier string. Throws on invalid input.</summary>
    public static ServerId Parse(string input)
    {
        if (!TryParse(input, out var id, out var error))
            throw new FormatException(error);
        return id;
    }

    /// <summary>Try to parse and validate a server identifier string.</summary>
    public static bool TryParse(string? input, out ServerId result, out string? error)
    {
        result = default;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Server identifier must not be empty.";
            return false;
        }

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            error = $"Server identifier is not a valid absolute URI: '{input}'.";
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            // Loopback exemption: allow http for localhost/127.0.0.1/::1
            if (!(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
            {
                error = "Server identifier MUST use the https scheme.";
                return false;
            }
        }

        // No path, query, or fragment.
        if (uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            error = "Server identifier MUST NOT contain path, query, or fragment.";
            return false;
        }

        // Trailing slash: the canonical form has no trailing slash.
        if (input.EndsWith('/'))
        {
            error = "Server identifier MUST NOT include a trailing slash.";
            return false;
        }

        // Port: not allowed for non-loopback.
        if (!uri.IsDefaultPort && !uri.IsLoopback)
        {
            error = "Server identifier MUST NOT contain a port (non-loopback).";
            return false;
        }

        // Lowercase enforcement.
        var host = uri.Host; // Uri.Host is already lowercased by System.Uri
        var scheme = uri.Scheme; // already lowercase

        // IDN → ACE (A-label) form.
        var idn = new IdnMapping();
        string aceHost;
        try
        {
            aceHost = idn.GetAscii(host);
        }
        catch (ArgumentException)
        {
            error = "Server identifier domain is not valid for IDN conversion.";
            return false;
        }

        // Reconstruct the canonical form.
        string canonical;
        if (!uri.IsDefaultPort && uri.IsLoopback)
        {
            canonical = $"{scheme}://{aceHost}:{uri.Port}";
        }
        else
        {
            canonical = $"{scheme}://{aceHost}";
        }

        // Lowercase check on original input (spec: MUST be lowercase).
        if (input != canonical && input.ToLowerInvariant() != input)
        {
            error = "Server identifier MUST be lowercase.";
            return false;
        }

        result = new ServerId(canonical);
        return true;
    }

    /// <inheritdoc/>
    public bool Equals(ServerId other) => string.Equals(_value, other._value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ServerId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => _value?.GetHashCode(StringComparison.Ordinal) ?? 0;

    /// <inheritdoc/>
    public override string ToString() => _value ?? string.Empty;

    /// <summary>Equality operator.</summary>
    public static bool operator ==(ServerId left, ServerId right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(ServerId left, ServerId right) => !left.Equals(right);
}
