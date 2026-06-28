using System;
using System.Linq;
using AAuth.Server;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthInteractionCodeTests
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    [Fact]
    public void Generate_DefaultIsAtLeast40Bits()
    {
        var code = AAuthInteractionCode.Generate();
        Assert.True(code.Length >= 8); // 8 Crockford symbols = 40 bits
        Assert.All(code, c => Assert.Contains(c, Alphabet));
    }

    [Fact]
    public void Generate_OmitsAmbiguousLetters()
    {
        // Across many samples, never emit I, L, O, or U.
        for (var i = 0; i < 200; i++)
        {
            var code = AAuthInteractionCode.Generate(16);
            Assert.DoesNotContain(code, c => c is 'I' or 'L' or 'O' or 'U');
        }
    }

    [Fact]
    public void Generate_FewerThan8Symbols_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AAuthInteractionCode.Generate(7));
    }

    [Fact]
    public void Generate_ProducesDistinctCodes()
    {
        var codes = Enumerable.Range(0, 500).Select(_ => AAuthInteractionCode.Generate()).ToHashSet();
        Assert.Equal(500, codes.Count);
    }

    [Theory]
    [InlineData("A1B2-C3D4", "A1B2C3D4")]
    [InlineData("a1b2c3d4", "A1B2C3D4")]
    [InlineData("OIL0", "0110")] // O->0, I->1, L->1, 0 stays
    public void Normalize_StripsHyphens_Uppercases_FoldsAliases(string input, string expected)
    {
        Assert.Equal(expected, AAuthInteractionCode.Normalize(input));
    }

    [Fact]
    public void Matches_IsHyphenCaseAndAliasInsensitive()
    {
        Assert.True(AAuthInteractionCode.Matches("A1B2-C3D4", "a1b2c3d4"));
        Assert.True(AAuthInteractionCode.Matches("O1L0", "0110"));
        Assert.False(AAuthInteractionCode.Matches("A1B2C3D4", "A1B2C3D5"));
    }
}
