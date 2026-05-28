using AAuth;
using Xunit;

namespace AAuth.Tests;

public class AAuthTokenTypeTests
{
    [Theory]
    [InlineData("aa-agent+jwt", AAuthTokenType.AgentToken)]
    [InlineData("aa-auth+jwt", AAuthTokenType.AuthToken)]
    [InlineData("aa-resource+jwt", AAuthTokenType.ResourceToken)]
    [InlineData("naming+jwt", AAuthTokenType.NamingJwt)]
    public void ParseTokenType_KnownValues(string input, AAuthTokenType expected)
    {
        Assert.Equal(expected, AAuthTokenTypeExtensions.ParseTokenType(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unknown+jwt")]
    [InlineData("JWT")]
    public void ParseTokenType_UnknownValues_ReturnUnknown(string? input)
    {
        Assert.Equal(AAuthTokenType.Unknown, AAuthTokenTypeExtensions.ParseTokenType(input));
    }

    [Theory]
    [InlineData(AAuthTokenType.AgentToken, "aa-agent+jwt")]
    [InlineData(AAuthTokenType.AuthToken, "aa-auth+jwt")]
    [InlineData(AAuthTokenType.ResourceToken, "aa-resource+jwt")]
    [InlineData(AAuthTokenType.NamingJwt, "naming+jwt")]
    public void ToHeaderValue_RoundTrips(AAuthTokenType type, string expected)
    {
        Assert.Equal(expected, type.ToHeaderValue());
    }

    [Fact]
    public void ToHeaderValue_Unknown_Throws()
    {
        Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            AAuthTokenType.Unknown.ToHeaderValue());
    }
}
