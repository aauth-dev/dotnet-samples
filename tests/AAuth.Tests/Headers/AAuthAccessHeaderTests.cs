using System;
using AAuth;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Headers;

public class AAuthAccessHeaderTests
{
    [Fact]
    public void Name_IsAAuthAccessConstant()
    {
        Assert.Equal("AAuth-Access", AAuthAccessHeader.Name);
        Assert.Equal(AAuthConstants.Headers.AAuthAccess, AAuthAccessHeader.Name);
    }

    [Theory]
    [InlineData("abc123")]
    [InlineData("a")]
    [InlineData("AZaz09-._~+/")]
    [InlineData("eyJhbGc.payload.sig")]
    [InlineData("dGVzdA==")] // trailing '=' padding
    [InlineData("dGVzdA=")]
    public void IsValidToken68_AcceptsValidValues(string value)
    {
        Assert.True(AAuthAccessHeader.IsValidToken68(value));
        Assert.Equal(value, AAuthAccessHeader.ValidateToken68(value));
    }

    [Theory]
    [InlineData("")] // empty
    [InlineData(" ")] // whitespace only
    [InlineData("abc def")] // embedded whitespace / second credential
    [InlineData("abc\tdef")] // embedded tab
    [InlineData("abc\u0001def")] // control character
    [InlineData("=abc")] // padding before any base char
    [InlineData("=")] // padding only
    [InlineData("abc=def")] // base char after padding
    [InlineData("abc,def")] // comma (multiple credentials)
    [InlineData("abc\"def")] // illegal character
    public void IsValidToken68_RejectsInvalidValues(string value)
    {
        Assert.False(AAuthAccessHeader.IsValidToken68(value));
        Assert.Throws<FormatException>(() => AAuthAccessHeader.ValidateToken68(value));
    }

    [Fact]
    public void IsValidToken68_NullIsInvalid()
    {
        Assert.False(AAuthAccessHeader.IsValidToken68(null));
    }

    [Fact]
    public void FormatAuthorization_RoundTrips()
    {
        var header = AAuthAccessHeader.FormatAuthorization("opaque-token-value");
        Assert.Equal("AAuth opaque-token-value", header);
        Assert.Equal("opaque-token-value", AAuthAccessHeader.ParseAuthorization(header));
    }

    [Fact]
    public void FormatAccess_RoundTrips()
    {
        var header = AAuthAccessHeader.FormatAccess("opaque-token-value");
        Assert.Equal("opaque-token-value", header);
        Assert.Equal("opaque-token-value", AAuthAccessHeader.ParseAccess(header));
    }

    [Theory]
    [InlineData("AAuth abc123", "abc123")]
    [InlineData("aauth abc123", "abc123")] // scheme is case-insensitive
    [InlineData("AAuth   abc123", "abc123")] // extra separating spaces
    [InlineData("  AAuth abc123  ", "abc123")] // surrounding whitespace
    public void ParseAuthorization_AcceptsValid(string header, string expected)
    {
        Assert.True(AAuthAccessHeader.TryParseAuthorization(header, out var token));
        Assert.Equal(expected, token);
        Assert.Equal(expected, AAuthAccessHeader.ParseAuthorization(header));
    }

    [Theory]
    [InlineData("Bearer abc123")] // wrong scheme
    [InlineData("AAuth")] // no credential
    [InlineData("AAuth ")] // empty credential
    [InlineData("AAuth abc def")] // second credential
    [InlineData("AAuth abc,def")] // comma list
    [InlineData("abc123")] // no scheme
    public void ParseAuthorization_RejectsInvalid(string header)
    {
        Assert.False(AAuthAccessHeader.TryParseAuthorization(header, out _));
        Assert.Throws<FormatException>(() => AAuthAccessHeader.ParseAuthorization(header));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc def")]
    [InlineData("abc,def")]
    public void ParseAccess_RejectsInvalid(string header)
    {
        Assert.False(AAuthAccessHeader.TryParseAccess(header, out _));
        Assert.Throws<FormatException>(() => AAuthAccessHeader.ParseAccess(header));
    }
}
