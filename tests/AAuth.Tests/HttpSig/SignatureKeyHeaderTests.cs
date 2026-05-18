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

    [Fact]
    public void Parse_JwtScheme()
    {
        var (scheme, parameters) = SignatureKeyHeader.Parse("sig=jwt;jwt=\"eyJ.X.Y\"");

        Assert.Equal("jwt", scheme);
        Assert.Equal("eyJ.X.Y", parameters["jwt"]);
    }

    [Fact]
    public void TryGetJwt_Roundtrip()
    {
        var header = SignatureKeyHeader.FormatJwt("abc.def.ghi");
        Assert.Equal("abc.def.ghi", SignatureKeyHeader.TryGetJwt(header));
    }

    [Fact]
    public void TryGetJwt_OtherSchemeReturnsNull()
    {
        Assert.Null(SignatureKeyHeader.TryGetJwt("sig=hwk;jwk=\"{}\""));
    }

    [Fact]
    public void Parse_Malformed_Throws()
    {
        Assert.Throws<FormatException>(() => SignatureKeyHeader.Parse("bogus"));
        Assert.Throws<FormatException>(() => SignatureKeyHeader.Parse("sig=jwt;jwt=\"unterminated"));
    }
}
