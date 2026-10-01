using System.Text.Json.Nodes;
using AAuth.Person;

namespace MockPersonServer;

/// <summary>
/// What a consent screen should show as the request. An R3 resource token carries
/// <c>r3_uri</c>/<c>r3_s256</c> in place of <c>scope</c> (R3 §Resource Token Extensions),
/// so the SDK fills <see cref="PersonPendingEntry.Scope"/> with the PS default scope.
/// That default is not what the resource asked for and must not be shown as such.
/// </summary>
internal static class ConsentDisplay
{
    public static string? R3Uri(PersonPendingEntry entry) => Text(entry.ResourceContext, "r3_uri");

    public static string? Scope(PersonPendingEntry entry) =>
        R3Uri(entry) is not null && string.IsNullOrWhiteSpace(Text(entry.ResourceContext, "scope")) ? null : entry.Scope;

    private static string? Text(JsonObject? document, string name) =>
        document?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
}
