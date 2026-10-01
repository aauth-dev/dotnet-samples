using System.Reflection;
using AAuth.Access;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server;
using Xunit;

namespace AAuth.Tests.Api;

/// <summary>Every bound or configured option property has a row in docs/reference/configuration.md.</summary>
public class ConfigurationReferenceTests
{
    [Theory]
    [InlineData(typeof(AAuthAgentOptions), "AAuthAgentOptions (AddAAuthAgent)")]
    [InlineData(typeof(AAuthSelfIssuedAgentOptions), "AAuthAgentOptions (AddAAuthAgent)")]
    [InlineData(typeof(AAuthAgentProviderOptions), "AAuthAgentOptions (AddAAuthAgent)")]
    [InlineData(typeof(AAuthJwksUriIdentityOptions), "AAuthAgentOptions (AddAAuthAgent)")]
    [InlineData(typeof(AAuthResourceOptions), "AAuthResourceOptions (AddAAuthResource)")]
    [InlineData(typeof(AAuthPersonServerOptions), "AAuthPersonServerOptions (via AddAAuthPersonServer)")]
    [InlineData(typeof(AAuthAccessServerOptions), "AAuthAccessServerOptions (via AddAAuthAccessServer)")]
    [InlineData(typeof(AAuthTrustOptions), "AAuthTrustOptions")]
    [InlineData(typeof(AAuthDiscoveryOptions), "AAuthDiscoveryOptions (AddAAuthDiscovery)")]
    [InlineData(typeof(ChallengeHandlingOptions), "ChallengeHandlingOptions (WithChallengeHandling)")]
    [InlineData(typeof(InteractionHandlingOptions), "InteractionHandlingOptions (WithInteractionHandling)")]
    public void Configuration_DocumentsEveryOption(Type options, string heading)
    {
        var section = Section(heading);
        var missing = options.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.SetMethod is { IsPublic: true } || IsNestedOptions(property))
            .Select(property => property.Name)
            .Where(name => !section.Contains($"| `{name}`", StringComparison.Ordinal)
                && !section.Contains($":{name}`", StringComparison.Ordinal))
            .ToArray();

        Assert.True(missing.Length == 0, $"{heading} does not document: {string.Join(", ", missing)}");
    }

    // Nested option objects (SelfIssued, AgentProvider, Challenge, ...) are get-only but bind.
    private static bool IsNestedOptions(PropertyInfo property)
        => property.SetMethod is null && property.PropertyType.Namespace?.StartsWith("AAuth", StringComparison.Ordinal) == true
            && property.PropertyType.IsClass && property.PropertyType.Name.EndsWith("Options", StringComparison.Ordinal);

    private static string Section(string heading)
    {
        var text = File.ReadAllText(Path.Combine(DocumentationInventory.Root, "docs/reference/configuration.md"));
        var start = text.IndexOf("### " + heading + "\n", StringComparison.Ordinal);
        Assert.True(start >= 0, $"configuration.md has no section '### {heading}'.");
        var body = text[(start + heading.Length + 5)..];
        var end = body.IndexOf("\n#", StringComparison.Ordinal);
        return end < 0 ? body : body[..end];
    }
}
