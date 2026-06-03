using System;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Headers;

public class AAuthInteractionTests
{
    [Fact]
    public void Format_RoundTrips_Through_ParsedRequirement()
    {
        var header = Interaction.Format("https://ps.example/interaction", "ABCD1234");
        var parsed = AAuthRequirementHeader.Parse(header);
        var interaction = Interaction.FromRequirement(parsed);

        Assert.NotNull(interaction);
        Assert.Equal("https://ps.example/interaction", interaction!.Url);
        Assert.Equal("ABCD1234", interaction.Code);
    }

    [Fact]
    public void FromRequirement_ReturnsNull_ForNonInteractionType()
    {
        var parsed = AAuthRequirementHeader.Parse(
            AAuthRequirementHeader.FormatAuthToken("eyJ.aGVsbG8.signature"));
        Assert.Null(Interaction.FromRequirement(parsed));
    }

    [Fact]
    public void FromRequirement_Throws_WhenInteractionParametersMissing()
    {
        var parsed = AAuthRequirementHeader.Parse("requirement=interaction; url=\"https://ps/i\"");
        Assert.Throws<FormatException>(() => Interaction.FromRequirement(parsed));
    }

    [Fact]
    public void BuildUserUrl_AppendsCodeAsQueryParameter()
    {
        var i = new Interaction("https://ps.example/interaction", "ABCD/1234");
        Assert.Equal(
            "https://ps.example/interaction?code=ABCD%2F1234",
            i.BuildUserUrl());
    }

    [Fact]
    public void BuildUserUrl_PreservesExistingQuery_AndAppendsCallback()
    {
        var i = new Interaction("https://ps.example/interaction?ref=foo", "XYZ");
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
        Assert.Throws<ArgumentException>(() => Interaction.Format(url, code));
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com")]
    [InlineData("relative/path")]
    public void Format_RejectsNonHttpsSchemes(string url)
    {
        Assert.Throws<ArgumentException>(() => Interaction.Format(url, "ABCD"));
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>")]
    [InlineData("file:///etc/passwd")]
    public void FromRequirement_RejectsNonHttpsSchemes(string url)
    {
        // Construct the header manually to bypass Format()'s own validation
        // and verify the parser-side guard also fires (defense in depth —
        // a malicious PS could emit the header bytes directly).
        var raw = $"requirement=interaction; url=\"{url}\"; code=\"ABCD\"";
        var parsed = AAuthRequirementHeader.Parse(raw);
        Assert.Throws<FormatException>(() => Interaction.FromRequirement(parsed));
    }

    [Fact]
    public void FromRequirement_AllowsLoopbackHttp()
    {
        var raw = "requirement=interaction; url=\"http://localhost:5100/interaction\"; code=\"ABCD\"";
        var parsed = AAuthRequirementHeader.Parse(raw);
        var i = Interaction.FromRequirement(parsed);
        Assert.NotNull(i);
        Assert.Equal("http://localhost:5100/interaction", i!.Url);
    }
}
