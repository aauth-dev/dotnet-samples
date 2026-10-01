using System;

namespace AAuth.Person;

/// <summary>
/// Stable Person Server-internal key for the accountable person bound to an agent.
/// This value is never emitted in AAuth protocol tokens; directed <c>sub</c>
/// values are derived from it per resource.
/// </summary>
public readonly record struct AAuthPersonKey
{
    /// <summary>Create a non-empty opaque person key.</summary>
    public AAuthPersonKey(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    /// <summary>The opaque stable key value.</summary>
    public string Value { get; }

    /// <inheritdoc />
    public override string ToString() => Value;
}
