using AAuth.Identifiers;
using Xunit;

namespace AAuth.Conformance.Identifiers;

/// <summary>
/// Conformance tests for agent identifiers per §Agent Identifiers.
/// </summary>
public class AgentIdTests
{
    [Theory(DisplayName = "§Agent Identifiers — valid format accepted")]
    [InlineData("aauth:assistant-v2@agent.example")]
    [InlineData("aauth:cli+instance.1@tools.example")]
    [InlineData("aauth:a@x.co")]
    [InlineData("aauth:test_user@domain.example")]
    public void ValidIdentifiers_Accepted(string input)
    {
        Assert.True(AAuthAgentId.TryParse(input, out var id, out _));
        Assert.Equal(input, id.Value);
    }

    [Fact(DisplayName = "§Agent Identifiers — uppercase rejected")]
    public void Rejects_Uppercase()
    {
        Assert.False(AAuthAgentId.TryParse("aauth:MyAgent@agent.example", out _, out var err));
        Assert.Contains("invalid character", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — missing 'aauth:' rejected")]
    public void Rejects_MissingScheme()
    {
        Assert.False(AAuthAgentId.TryParse("assistant@agent.example", out _, out var err));
        Assert.Contains("aauth:", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — empty local part rejected")]
    public void Rejects_EmptyLocal()
    {
        Assert.False(AAuthAgentId.TryParse("aauth:@agent.example", out _, out var err));
        Assert.Contains("local part must not be empty", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — local part > 255 rejected")]
    public void Rejects_LongLocal()
    {
        var longLocal = new string('a', 256);
        Assert.False(AAuthAgentId.TryParse($"aauth:{longLocal}@agent.example", out _, out var err));
        Assert.Contains("255", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — invalid chars rejected (space)")]
    public void Rejects_Space()
    {
        Assert.False(AAuthAgentId.TryParse("aauth:my agent@agent.example", out _, out var err));
        Assert.Contains("invalid character", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — missing @ rejected")]
    public void Rejects_MissingAt()
    {
        Assert.False(AAuthAgentId.TryParse("aauth:agentnoat", out _, out var err));
        Assert.Contains("@", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — uppercase domain rejected")]
    public void Rejects_UppercaseDomain()
    {
        Assert.False(AAuthAgentId.TryParse("aauth:agent@Agent.Example", out _, out var err));
        Assert.Contains("lowercase", err!);
    }

    [Fact(DisplayName = "§Agent Identifiers — case-sensitive exact comparison")]
    public void ExactComparison()
    {
        var id1 = AAuthAgentId.Parse("aauth:alice@ap.example");
        var id2 = AAuthAgentId.Parse("aauth:alice@ap.example");
        Assert.Equal(id1, id2);
    }

    [Fact(DisplayName = "§Agent Identifiers — local and domain parts extracted")]
    public void PartsExtracted()
    {
        var id = AAuthAgentId.Parse("aauth:alice@ap.example");
        Assert.Equal("alice", id.Local);
        Assert.Equal("ap.example", id.Domain);
    }
}
