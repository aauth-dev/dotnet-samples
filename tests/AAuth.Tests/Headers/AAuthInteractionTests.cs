using System;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Headers;

public class AAuthInteractionTests
{
    [Fact]
    public void Format_RoundTrips_Through_ParsedRequirement()
    {
        var header = AAuthInteraction.Format("https://ps.example/interaction", "ABCD1234");
        var parsed = AAuthRequirementHeader.Parse(header);
        var interaction = AAuthInteraction.FromRequirement(parsed);

        Assert.NotNull(interaction);
        Assert.Equal("https://ps.example/interaction", interaction!.Url);
        Assert.Equal("ABCD1234", interaction.Code);
    }

    [Fact]
    public void FromRequirement_ReturnsNull_ForNonInteractionType()
    {
        var parsed = AAuthRequirementHeader.Parse(
            AAuthRequirementHeader.FormatAuthToken("eyJ.aGVsbG8.signature"));
        Assert.Null(AAuthInteraction.FromRequirement(parsed));
    }

    [Fact]
    public void FromRequirement_Throws_WhenInteractionParametersMissing()
    {
        var parsed = AAuthRequirementHeader.Parse("requirement=interaction; url=\"https://ps/i\"");
        Assert.Throws<FormatException>(() => AAuthInteraction.FromRequirement(parsed));
    }

    [Fact]
    public void BuildUserUrl_AppendsCodeAsQueryParameter()
    {
        var i = new AAuthInteraction("https://ps.example/interaction", "ABCD/1234");
        Assert.Equal(
            "https://ps.example/interaction?code=ABCD%2F1234",
            i.BuildUserUrl());
    }

    [Fact]
    public void BuildUserUrl_PreservesExistingQuery_AndAppendsCallback()
    {
        var i = new AAuthInteraction("https://ps.example/interaction?ref=foo", "XYZ");
        Assert.Equal(
            "https://ps.example/interaction?ref=foo&code=XYZ&callback=https%3A%2F%2Fagent.example%2Fcb",
            i.BuildUserUrl("https://agent.example/cb"));
    }

    [Theory]
    [InlineData("https://ps.example/interaction", "\"")]
    [InlineData("https://ps.example/interaction", "\\")]
    [InlineData("https://ps.example/interaction", "\x01")]
    [InlineData("\"", "code")]
    public void Format_RejectsControlCharactersAndQuotes(string url, string code)
    {
        Assert.Throws<ArgumentException>(() => AAuthInteraction.Format(url, code));
    }
}
