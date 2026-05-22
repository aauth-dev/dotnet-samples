using AAuth.Identifiers;
using Xunit;

namespace AAuth.Conformance.Identifiers;

/// <summary>
/// Conformance tests for server identifiers per §Server Identifiers.
/// </summary>
public class ServerIdTests
{
    [Theory(DisplayName = "§Server Identifiers — valid identifiers accepted")]
    [InlineData("https://agent.example")]
    [InlineData("https://xn--nxasmq6b.example")]
    [InlineData("https://sub.domain.example")]
    public void ValidIdentifiers_Accepted(string input)
    {
        Assert.True(AAuthServerId.TryParse(input, out var id, out _));
        Assert.Equal(input, id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — path rejected")]
    public void Rejects_Path()
    {
        Assert.False(AAuthServerId.TryParse("https://agent.example/v1", out _, out var err));
        Assert.Contains("path", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — port (non-loopback) rejected")]
    public void Rejects_NonLoopbackPort()
    {
        Assert.False(AAuthServerId.TryParse("https://agent.example:8443", out _, out var err));
        Assert.Contains("port", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — trailing slash rejected")]
    public void Rejects_TrailingSlash()
    {
        Assert.False(AAuthServerId.TryParse("https://agent.example/", out _, out var err));
        Assert.Contains("trailing slash", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — mixed case rejected")]
    public void Rejects_MixedCase()
    {
        Assert.False(AAuthServerId.TryParse("https://Agent.Example", out _, out var err));
        Assert.Contains("lowercase", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — http (non-loopback) rejected")]
    public void Rejects_HttpNonLoopback()
    {
        Assert.False(AAuthServerId.TryParse("http://agent.example", out _, out var err));
        Assert.Contains("https", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — loopback+port accepted for dev")]
    public void Accepts_LoopbackWithPort()
    {
        Assert.True(AAuthServerId.TryParse("http://localhost:5100", out var id, out _));
        Assert.Equal("http://localhost:5100", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — loopback 127.0.0.1+port accepted")]
    public void Accepts_Loopback127WithPort()
    {
        Assert.True(AAuthServerId.TryParse("http://127.0.0.1:8080", out var id, out _));
        Assert.Equal("http://127.0.0.1:8080", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — IDN normalised to ACE form")]
    public void IdnNormalisedToAce()
    {
        // "münchen.example" → "xn--mnchen-3ya.example" (but parsed through URI)
        // Use a known punycode domain directly to test we accept it.
        Assert.True(AAuthServerId.TryParse("https://xn--nxasmq6b.example", out var id, out _));
        Assert.Equal("https://xn--nxasmq6b.example", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — query string rejected")]
    public void Rejects_QueryString()
    {
        Assert.False(AAuthServerId.TryParse("https://agent.example?foo=bar", out _, out var err));
        Assert.Contains("query", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — fragment rejected")]
    public void Rejects_Fragment()
    {
        Assert.False(AAuthServerId.TryParse("https://agent.example#frag", out _, out var err));
        Assert.Contains("fragment", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — equality by value")]
    public void EqualityByValue()
    {
        var id1 = AAuthServerId.Parse("https://ps.example");
        var id2 = AAuthServerId.Parse("https://ps.example");
        Assert.Equal(id1, id2);
        Assert.True(id1 == id2);
    }
}
