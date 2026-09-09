using System;

namespace AAuth;

/// <summary>
/// Shared URL validation helpers used by token builders, well-known endpoint
/// validation, and sample wiring.
/// </summary>
/// <remarks>
/// Identifier validation operates on the original string. Development exceptions
/// require an explicit policy containing exact loopback origins.
/// </remarks>
internal static class AAuthUrl
{
    /// <summary>
    /// Validate an exact server identifier against the selected policy.
    /// </summary>
    public static bool IsHttpsOrLoopback(string value, Discovery.AAuthEgressPolicy? policy = null) =>
        (policy ?? Discovery.AAuthEgressPolicy.Production).IsValidIdentifier(value);
}
