using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class TokenVerifierTests
{
    [Fact]
    public void VerifySelfIssuedAgentToken_AcceptsHappyPath()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
        var verified = verifier.VerifySelfIssuedAgentToken(jwt, key);

        Assert.Equal("aa-agent+jwt", verified.TokenType);
        Assert.Equal("https://ap.example", verified.Issuer);
    }

    [Fact]
    public void Verify_RejectsExpiredToken()
    {
        var key = AAuthKey.Generate();
        var issued = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
            IssuedAt = issued,
            Lifetime = TimeSpan.FromMinutes(1),
        }.Build();

        var verifier = new TokenVerifier { Clock = () => issued.AddHours(1) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, key));
    }

    [Fact]
    public void Verify_RejectsWrongTyp()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
        Assert.Throws<TokenVerificationException>(() =>
            verifier.Verify(jwt, key, "aa-resource+jwt", "aauth-resource.json"));
    }

    [Fact]
    public void Verify_RejectsWrongAudience()
    {
        var key = AAuthKey.Generate();
        var rkey = AAuthKey.Generate();
        var jwt = new ResourceTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            Agent = "aauth:a@ap.example",
            AgentJkt = key.ComputeJwkThumbprint(),
            Key = rkey,
            KeyId = "r",
        }.Build();

        var verifier = new TokenVerifier();
        Assert.Throws<TokenVerificationException>(() =>
            verifier.Verify(jwt, rkey, "aa-resource+jwt", "aauth-resource.json", "https://other.example"));
    }

    [Fact]
    public void Verify_RejectsBadSignature()
    {
        var key = AAuthKey.Generate();
        var other = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, other));
    }
}
