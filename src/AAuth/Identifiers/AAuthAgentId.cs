using System;

namespace AAuth.Identifiers;

/// <summary>
/// Validates and normalises an AAuth agent identifier per §Agent Identifiers.
/// Format: <c>aauth:local@domain</c> where local is [a-z0-9\-_+.]{1,255}
/// and domain is a valid server identifier domain.
/// </summary>
public readonly struct AAuthAgentId : IEquatable<AAuthAgentId>
{
    private readonly string _value;

    private AAuthAgentId(string value) => _value = value;

    /// <summary>The validated identifier value.</summary>
    public string Value => _value;

    /// <summary>The local part (before @).</summary>
    public string Local => _value[6.._value.IndexOf('@')];

    /// <summary>The domain part (after @).</summary>
    public string Domain => _value[(_value.IndexOf('@') + 1)..];

    /// <summary>Parse and validate an agent identifier. Throws on invalid input.</summary>
    public static AAuthAgentId Parse(string input)
    {
        if (!TryParse(input, out var id, out var error))
            throw new FormatException(error);
        return id;
    }

    /// <summary>Try to parse and validate an agent identifier.</summary>
    public static bool TryParse(string? input, out AAuthAgentId result, out string? error)
    {
        result = default;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Agent identifier must not be empty.";
            return false;
        }

        // Must start with "aauth:"
        if (!input.StartsWith("aauth:", StringComparison.Ordinal))
        {
            error = "Agent identifier must start with 'aauth:'.";
            return false;
        }

        var rest = input.AsSpan(6); // after "aauth:"
        var atIndex = rest.IndexOf('@');
        if (atIndex < 0)
        {
            error = "Agent identifier must contain '@' separating local and domain parts.";
            return false;
        }

        var local = rest[..atIndex];
        var domain = rest[(atIndex + 1)..];

        // Local part validation.
        if (local.Length == 0)
        {
            error = "Agent identifier local part must not be empty.";
            return false;
        }
        if (local.Length > 255)
        {
            error = "Agent identifier local part must not exceed 255 characters.";
            return false;
        }
        for (int i = 0; i < local.Length; i++)
        {
            var c = local[i];
            if (!IsValidLocalChar(c))
            {
                error = $"Agent identifier local part contains invalid character '{c}' at position {i}. " +
                        "Allowed: a-z, 0-9, hyphen, underscore, plus, period.";
                return false;
            }
        }

        // Domain part: must be a valid domain (matches server identifier domain rules).
        if (domain.Length == 0)
        {
            error = "Agent identifier domain part must not be empty.";
            return false;
        }
        // Domain must be lowercase.
        for (int i = 0; i < domain.Length; i++)
        {
            if (char.IsUpper(domain[i]))
            {
                error = "Agent identifier domain must be lowercase.";
                return false;
            }
        }

        result = new AAuthAgentId(input);
        return true;
    }

    private static bool IsValidLocalChar(char c) =>
        c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '+' or '.';

    /// <inheritdoc/>
    public bool Equals(AAuthAgentId other) => string.Equals(_value, other._value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is AAuthAgentId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => _value?.GetHashCode(StringComparison.Ordinal) ?? 0;

    /// <inheritdoc/>
    public override string ToString() => _value ?? string.Empty;

    /// <summary>Equality operator.</summary>
    public static bool operator ==(AAuthAgentId left, AAuthAgentId right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(AAuthAgentId left, AAuthAgentId right) => !left.Equals(right);
}
