using StructuredFieldValues;

namespace AAuth.Tests.HttpSig;

public class StructuredFieldsCompatibilityTests
{
    [Fact]
    public void DictionaryPreservesWireTypesAndEscapes()
    {
        var error = SfvParser.ParseDictionary(
            "other=unknown, chosen=hwk;kty=\"OKP\";created=123;flag;raw=:AQID:;escaped=\"a\\\"b\\\\c\", input=(\"@method\" \"signature-key\");created=123, signature=:AQID:",
            out var dictionary);

        Assert.Null(error);
        Assert.Equal(4, dictionary.Count);
        Assert.NotEqual(typeof(string), dictionary["chosen"].Value.GetType());
        Assert.Equal("OKP", Assert.IsType<string>(dictionary["chosen"].Parameters["kty"]));
        Assert.Equal(123L, Assert.IsType<long>(dictionary["chosen"].Parameters["created"]));
        Assert.True(Assert.IsType<bool>(dictionary["chosen"].Parameters["flag"]));
        Assert.Equal(new byte[] { 1, 2, 3 }, Assert.IsType<ReadOnlyMemory<byte>>(dictionary["signature"].Value).ToArray());
        Assert.Equal("a\"b\\c", Assert.IsType<string>(dictionary["chosen"].Parameters["escaped"]));
        Assert.IsAssignableFrom<IReadOnlyList<ParsedItem>>(dictionary["input"].Value);
    }

    [Theory]
    [InlineData("sig=hwk;kty=\"unterminated")]
    [InlineData("sig=jwt;jwt=\"bad\\escape\"")]
    [InlineData("sig=:not base64:")]
    public void MalformedDictionaryReturnsAnError(string wire)
    {
        Assert.NotNull(SfvParser.ParseDictionary(wire, out _));
    }
}