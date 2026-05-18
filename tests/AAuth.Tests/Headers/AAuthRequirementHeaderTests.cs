using System;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Headers;

public class AAuthRequirementHeaderTests
{
    [Fact]
    public void FormatAuthToken_QuotesResourceToken()
    {
        var formatted = AAuthRequirementHeader.FormatAuthToken("abc.def.ghi");
        Assert.Equal("requirement=auth-token; resource-token=\"abc.def.ghi\"", formatted);
    }

    [Fact]
    public void Parse_RoundTripsAuthToken()
    {
        var formatted = AAuthRequirementHeader.FormatAuthToken("xyz.123.abc");
        var parsed = AAuthRequirementHeader.Parse(formatted);

        Assert.Equal("auth-token", parsed.Requirement);
        Assert.Equal("xyz.123.abc", parsed.ResourceToken);
    }

    [Fact]
    public void Parse_AcceptsOtherRequirementTypes()
    {
        var parsed = AAuthRequirementHeader.Parse("requirement=interaction; url=\"https://ps.example/i\"; code=\"abc\"");
        Assert.Equal("interaction", parsed.Requirement);
        Assert.Equal("https://ps.example/i", parsed.Parameters["url"]);
        Assert.Equal("abc", parsed.Parameters["code"]);
    }

    [Fact]
    public void FormatAuthToken_RejectsControlCharacters()
    {
        Assert.Throws<ArgumentException>(() => AAuthRequirementHeader.FormatAuthToken("abc\ndef"));
    }
}
