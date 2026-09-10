using System.Collections.Generic;

namespace AAuth.Testing;

internal static class TestScopeDefinitions
{
    internal static IReadOnlyDictionary<string, string> Resource { get; } = new Dictionary<string, string>
    {
        ["read"] = "Read test records",
        ["write"] = "Write test records",
        ["data.read"] = "Read test data",
        ["data.write"] = "Write test data",
        ["data:read"] = "Read colon-scope test data",
        ["whoami"] = "Read test identity",
        ["calendar.read"] = "Read calendar",
        ["wallet.read"] = "Read wallet",
        ["wallet.charge"] = "Charge wallet",
        ["trips.read"] = "Read trips",
        ["trips.book"] = "Book trips",
    };
}