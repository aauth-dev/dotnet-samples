using System;
using System.Globalization;

namespace AAuth.Identifiers;

/// <summary>
/// Validates an exact AAuth server identifier without normalization.
/// Loopback exceptions require an explicit development policy.
/// </summary>
public readonly struct ServerId : IEquatable<ServerId>
{
    private readonly string _value;

    private ServerId(string value) => _value = value;

    /// <summary>The original validated identifier value.</summary>
    public string Value => _value;

    /// <summary>Parse and validate a server identifier string. Throws on invalid input.</summary>
    public static ServerId Parse(string input, AAuth.Discovery.AAuthEgressPolicy? policy = null)
    {
        if (!TryParse(input, out var id, out var error, policy))
            throw new FormatException(error);
        return id;
    }

    /// <summary>Try to parse and validate a server identifier string.</summary>
    public static bool TryParse(string? input, out ServerId result, out string? error,
        AAuth.Discovery.AAuthEgressPolicy? policy = null)
    {
        result = default;
        error = null;

        if (!(policy ?? AAuth.Discovery.AAuthEgressPolicy.Production).IsValidIdentifier(input))
        {
            error = "Server identifier requires lowercase https and an ASCII host, without port, path, query, fragment, or trailing slash; loopback requires explicit configuration.";
            return false;
        }

        result = new ServerId(input!);
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
