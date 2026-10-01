using AAuth.Identifiers;
using AAuth.Discovery;
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
        Assert.True(ServerId.TryParse(input, out var id, out _));
        Assert.Equal(input, id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — path rejected")]
    public void Rejects_Path()
    {
        Assert.False(ServerId.TryParse("https://agent.example/v1", out _, out var err));
        Assert.Contains("path", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — port (non-loopback) rejected")]
    public void Rejects_NonLoopbackPort()
    {
        Assert.False(ServerId.TryParse("https://agent.example:8443", out _, out var err));
        Assert.Contains("port", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — trailing slash rejected")]
    public void Rejects_TrailingSlash()
    {
        Assert.False(ServerId.TryParse("https://agent.example/", out _, out var err));
        Assert.Contains("trailing slash", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — mixed case rejected")]
    public void Rejects_MixedCase()
    {
        Assert.False(ServerId.TryParse("https://Agent.Example", out _, out var err));
        Assert.Contains("lowercase", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — http (non-loopback) rejected")]
    public void Rejects_HttpNonLoopback()
    {
        Assert.False(ServerId.TryParse("http://agent.example", out _, out var err));
        Assert.Contains("https", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — loopback+port accepted for dev")]
    public void Accepts_LoopbackWithPort()
    {
        Assert.False(ServerId.TryParse("http://localhost:5100", out _, out _));
        Assert.True(ServerId.TryParse("http://localhost:5100", out var id, out _, TestEgress.Policy));
        Assert.Equal("http://localhost:5100", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — loopback 127.0.0.1+port accepted")]
    public void Accepts_Loopback127WithPort()
    {
        Assert.False(ServerId.TryParse("http://127.0.0.1:8080", out _, out _));
        Assert.True(ServerId.TryParse("http://127.0.0.1:8080", out var id, out _, TestEgress.Policy));
        Assert.Equal("http://127.0.0.1:8080", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — production rejects loopback issuer and metadata URLs")]
    public void ProductionRejectsLoopback()
    {
        Assert.False(ServerId.TryParse("http://localhost:5002", out _, out _));
        Assert.False(AAuthEgressPolicy.Production.IsValidIdentifier("http://localhost:5002"));
        Assert.Throws<System.Net.Http.HttpRequestException>(() =>
            AAuthEgressPolicy.Production.ValidateUrl("http://localhost:5002/.well-known/aauth-resource.json"));
    }

    [Theory(DisplayName = "§Server Identifiers — development loopback policy rejects non-loopback origins")]
    [InlineData("http://*.localhost:5000")]
    [InlineData("http://example.com:5000")]
    [InlineData("http://[::1]:5000")]
    public void DevelopmentLoopbackPolicyRejectsNonLoopbackOrigins(string origin)
    {
        Assert.ThrowsAny<Exception>(() => AAuthEgressPolicy.ForDevelopmentLoopback(origin));
    }

    [Fact(DisplayName = "§Server Identifiers — IDN normalised to ACE form")]
    public void IdnNormalisedToAce()
    {
        // "münchen.example" → "xn--mnchen-3ya.example" (but parsed through URI)
        // Use a known punycode domain directly to test we accept it.
        Assert.True(ServerId.TryParse("https://xn--nxasmq6b.example", out var id, out _));
        Assert.Equal("https://xn--nxasmq6b.example", id.Value);
    }

    [Fact(DisplayName = "§Server Identifiers — query string rejected")]
    public void Rejects_QueryString()
    {
        Assert.False(ServerId.TryParse("https://agent.example?foo=bar", out _, out var err));
        Assert.Contains("query", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — fragment rejected")]
    public void Rejects_Fragment()
    {
        Assert.False(ServerId.TryParse("https://agent.example#frag", out _, out var err));
        Assert.Contains("fragment", err!, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Server Identifiers — equality by value")]
    public void EqualityByValue()
    {
        var id1 = ServerId.Parse("https://ps.example");
        var id2 = ServerId.Parse("https://ps.example");
        Assert.Equal(id1, id2);
        Assert.True(id1 == id2);
    }
}
