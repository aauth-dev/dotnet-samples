using System;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Tests;

public class SignatureKeyHeaderTests
{
    [Fact]
    public void FormatJwt_Wraps()
    {
        var value = SignatureKeyHeader.FormatJwt("eyJ.HEADER.PAYLOAD");
        Assert.Equal("sig=jwt;jwt=\"eyJ.HEADER.PAYLOAD\"", value);
    }

    [Fact]
    public void FormatJwt_RejectsQuotes()
    {
        Assert.Throws<ArgumentException>(() => SignatureKeyHeader.FormatJwt("ey\"J"));
    }

    [Theory]
    [InlineData("ey\rJ")]
    [InlineData("ey\nJ")]
    [InlineData("ey\tJ")]
    [InlineData("ey\u0000J")]
    [InlineData("ey\u007FJ")]
    [InlineData("ey\\J")]
    public void FormatJwt_RejectsControlCharsAndBackslash(string jwt)
    {
        Assert.Throws<ArgumentException>(() => SignatureKeyHeader.FormatJwt(jwt));
    }

    [Fact]
    public void Parse_JwtScheme()
    {
        var (scheme, parameters) = SignatureKeyHeader.Parse("sig=jwt;jwt=\"eyJ.X.Y\"");

        Assert.Equal("jwt", scheme);
        Assert.Equal("eyJ.X.Y", parameters["jwt"]);
    }

    [Fact]
    public void GetJwt_Roundtrip()
    {
        var header = SignatureKeyHeader.FormatJwt("abc.def.ghi");
        Assert.Equal("abc.def.ghi", SignatureKeyHeader.GetJwt(header));
    }

    [Fact]
    public void GetJwt_OtherSchemeReturnsNull()
    {
        Assert.Null(SignatureKeyHeader.GetJwt("sig=hwk;jwk=\"{}\""));
    }

    [Fact]
    public void Parse_Malformed_Throws()
    {
        Assert.Throws<FormatException>(() => SignatureKeyHeader.Parse("bogus"));
        Assert.Throws<FormatException>(() => SignatureKeyHeader.Parse("sig=jwt;jwt=\"unterminated"));
    }

    [Fact]
    public void Parse_InvalidEscapeInQuotedValue_Throws()
    {
        // RFC 8941 §3.3.3: only \" and \\ are legal escapes inside an sf-string.
        Assert.Throws<FormatException>(() => SignatureKeyHeader.Parse("sig=jwt;jwt=\"a\\nb\""));
    }

    [Fact]
    public void Parse_ValidEscapesInQuotedValue_Unescape()
    {
        var (_, parameters) = SignatureKeyHeader.Parse("sig=jwt;jwt=\"a\\\"b\\\\c\"");
        Assert.Equal("a\"b\\c", parameters["jwt"]);
    }
}
