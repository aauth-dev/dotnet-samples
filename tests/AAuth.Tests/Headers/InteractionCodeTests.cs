using System;
using System.Collections.Generic;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Headers;

/// <summary>
/// Unit coverage for <see cref="InteractionCode"/> — the SDK-owned Crockford
/// base32 generator/validator per §Interaction Code Format (draft-02).
/// </summary>
public class InteractionCodeTests
{
    [Fact(DisplayName = "§Interaction Code — generated codes use only the Crockford alphabet")]
    public void Generate_UsesCrockfordAlphabet()
    {
        for (var i = 0; i < 200; i++)
        {
            var code = InteractionCode.Generate();
            foreach (var c in code)
            {
                Assert.Contains(c, InteractionCode.Alphabet);
            }
        }
    }

    [Fact(DisplayName = "§Interaction Code — default length carries ≥ 40 bits of entropy (≥ 8 symbols)")]
    public void Generate_DefaultIsAtLeastEightSymbols()
    {
        var code = InteractionCode.Generate();
        Assert.True(code.Length >= InteractionCode.MinimumSymbols);
    }

    [Fact(DisplayName = "§Interaction Code — fewer than 8 symbols is rejected")]
    public void Generate_RejectsWeakLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => InteractionCode.Generate(7));
    }

    [Fact(DisplayName = "§Interaction Code — generated codes are unguessably unique")]
    public void Generate_ProducesDistinctCodes()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 1000; i++)
        {
            Assert.True(seen.Add(InteractionCode.Generate(10)));
        }
    }

    [Theory(DisplayName = "§Interaction Code — hyphens are presentational and stripped")]
    [InlineData("A1B2-C3D4", "A1B2C3D4")]
    [InlineData("AB-CD-EF-GH", "ABCDEFGH")]
    public void Normalize_StripsHyphens(string input, string expected)
    {
        Assert.Equal(expected, InteractionCode.Normalize(input));
    }

    [Theory(DisplayName = "§Interaction Code — comparison folds glyph aliases (I/L→1, O→0) and case")]
    [InlineData("01234567", "oI234567")] // O→0, I→1, mixed case
    [InlineData("ABCDEFGH", "abcdefgh")]
    [InlineData("1AB2-C3D4", "lab2c3d4")] // L→1 fold + hyphen strip
    public void Matches_IsCaseAndGlyphInsensitive(string expected, string actual)
    {
        Assert.True(InteractionCode.Matches(expected, actual));
    }

    [Fact(DisplayName = "§Interaction Code — a generated code matches its hyphenated, lower-cased echo")]
    public void Matches_RoundTripsGeneratedCode()
    {
        var code = InteractionCode.Generate(8);
        var grouped = code.Substring(0, 4) + "-" + code.Substring(4);
        Assert.True(InteractionCode.Matches(code, grouped.ToLowerInvariant()));
    }

    [Theory(DisplayName = "§Interaction Code — characters outside the alphabet are invalid")]
    [InlineData("ABCDEF!@")]
    [InlineData("        ")]
    public void Normalize_RejectsOutOfAlphabet(string input)
    {
        Assert.Null(InteractionCode.Normalize(input));
        Assert.False(InteractionCode.IsValid(input));
    }

    [Fact(DisplayName = "§Interaction Code — mismatched codes do not match")]
    public void Matches_RejectsDifferentCodes()
    {
        Assert.False(InteractionCode.Matches("ABCDEFGH", "ABCDEFGJ"));
        Assert.False(InteractionCode.Matches(null, "ABCDEFGH"));
        Assert.False(InteractionCode.Matches("ABCDEFGH", ""));
    }

    [Theory(DisplayName = "§Interaction Code — codes shorter than 40 bits never match")]
    [InlineData("ABC", "ABC")]      // identical but only 3 symbols
    [InlineData("ABCDEFG", "ABCDEFG")] // identical but only 7 symbols
    [InlineData("1AB", "LAB")]      // glyph-folds to the same short string
    public void Matches_RejectsTooShortCodes(string expected, string actual)
    {
        // Even when both sides normalize to the same value, a string carrying
        // fewer than the spec minimum (8 symbols / 40 bits) MUST NOT validate.
        Assert.False(InteractionCode.Matches(expected, actual));
    }
}
