using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance for the <c>Signature-Key</c> header per
/// draft-hardt-httpbis-signature-key-00 §Header Format.
/// </summary>
public class SignatureKeyHeaderTests
{
    /// <summary>
    /// "The header is a structured-field Dictionary whose key 'sig' carries
    /// a token naming the carrier-token scheme."
    /// </summary>
    [Fact(DisplayName = "§Header Format — produces structured-dict 'sig=jwt;jwt=\"...\"'")]
    public void Format_EmitsExpectedShape()
    {
        var formatted = SignatureKeyHeader.FormatJwt("a.b.c");
        Assert.Equal("sig=jwt;jwt=\"a.b.c\"", formatted);
    }

    /// <summary>
    /// "Parsers MUST recognize the 'jwt' scheme and extract the 'jwt'
    /// parameter."
    /// </summary>
    [Fact(DisplayName = "§Header Format — GetJwt round-trips the jwt parameter")]
    public void GetJwt_RoundTrips()
    {
        var jwt = SignatureKeyHeader.GetJwt(SignatureKeyHeader.FormatJwt("xyz.123.abc"));
        Assert.Equal("xyz.123.abc", jwt);
    }

    /// <summary>
    /// "Parsers MUST return no carrier token for unknown schemes."
    /// </summary>
    [Fact(DisplayName = "§Header Format — unknown scheme returns null")]
    public void GetJwt_UnknownSchemeReturnsNull()
    {
        Assert.Null(SignatureKeyHeader.GetJwt("sig=hwk;jwk=\"{}\""));
    }

    /// <summary>
    /// "Issuers MUST reject control characters in the JWT parameter value."
    /// </summary>
    [Fact(DisplayName = "§Header Format — MUST reject control chars in JWT")]
    public void Format_RejectsControlChars()
    {
        Assert.Throws<ArgumentException>(() => SignatureKeyHeader.FormatJwt("a\nb"));
    }

    /// <summary>
    /// "Verifiers MUST extract the public key from cnf.jwk inside the JWT
    /// carried by Signature-Key."
    /// </summary>
    [Fact(DisplayName = "§Header Format — parser extracts cnf.jwk for HTTP signature verification")]
    public void Parser_ExtractsConfirmationKey()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = key,
        }.Build();

        var parsed = SignatureKeyParser.Parse(SignatureKeyHeader.FormatJwt(jwt));
        Assert.Equal(key.ComputeJwkThumbprint(), parsed.ConfirmationKey.ComputeJwkThumbprint());
    }
}
