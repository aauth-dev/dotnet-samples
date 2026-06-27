using System;
using AAuth.Headers;
using Xunit;

namespace AAuth.Conformance.ResourceTokens;

/// <summary>
/// Conformance tests for the <c>AAuth-Access</c> / <c>Authorization: AAuth</c>
/// <c>token68</c> grammar (§AAuth-Access Response Header; RFC 9110 §11.2).
/// </summary>
public class AAuthAccessTokenGrammarTests
{
    [Fact(DisplayName = "§AAuth-Access — token68 accepts the RFC 9110 base alphabet")]
    public void Token68_AcceptsBaseAlphabet()
    {
        // 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        Assert.True(AAuthAccessHeader.IsValidToken68("AZaz09-._~+/"));
        Assert.True(AAuthAccessHeader.IsValidToken68("dGVzdA=="));
    }

    [Fact(DisplayName = "§AAuth-Access — recipients MUST reject empty values")]
    public void Token68_RejectsEmpty()
    {
        Assert.False(AAuthAccessHeader.IsValidToken68(string.Empty));
        Assert.Throws<FormatException>(() => AAuthAccessHeader.ValidateToken68(string.Empty));
    }

    [Fact(DisplayName = "§AAuth-Access — recipients MUST reject embedded whitespace")]
    public void Token68_RejectsEmbeddedWhitespace()
    {
        Assert.False(AAuthAccessHeader.IsValidToken68("abc def"));
        Assert.False(AAuthAccessHeader.IsValidToken68("abc\tdef"));
    }

    [Fact(DisplayName = "§AAuth-Access — recipients MUST reject control characters")]
    public void Token68_RejectsControlCharacters()
    {
        Assert.False(AAuthAccessHeader.IsValidToken68("abc\u0001def"));
        Assert.False(AAuthAccessHeader.IsValidToken68("abc\u007fdef"));
    }

    [Fact(DisplayName = "§AAuth-Access — recipients MUST reject more than one credential")]
    public void Token68_RejectsMultipleCredentials()
    {
        // A second credential (comma- or space-separated) cannot be a single token68.
        Assert.False(AAuthAccessHeader.IsValidToken68("abc,def"));
        Assert.False(AAuthAccessHeader.TryParseAuthorization("AAuth abc AAuth def", out _));
    }

    [Fact(DisplayName = "§AAuth-Access — Authorization: AAuth <token68> round-trips")]
    public void Authorization_RoundTrips()
    {
        var header = AAuthAccessHeader.FormatAuthorization("opaque-token-value");
        Assert.Equal("AAuth opaque-token-value", header);
        Assert.Equal("opaque-token-value", AAuthAccessHeader.ParseAuthorization(header));
    }
}
