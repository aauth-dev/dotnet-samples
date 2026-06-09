using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests;

public class AgentTokenBuilderTests
{
    private static AAuthKey NewKey() => AAuthKey.Generate();

    private static (JsonObject Header, JsonObject Payload, byte[] Signature, string SigningInput) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        var header = JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!.AsObject();
        var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
        var signingInput = parts[0] + "." + parts[1];
        return (header, payload, signature, signingInput);
    }

    [Theory]
    [InlineData("", "sub", "kid")]
    [InlineData(" ", "sub", "kid")]
    [InlineData("iss", "", "kid")]
    [InlineData("iss", " ", "kid")]
    [InlineData("iss", "sub", "")]
    [InlineData("iss", "sub", " ")]
    public void Build_RejectsEmptyRequiredClaims(string iss, string sub, string kid)
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = iss,
            Subject = sub,
            KeyId = kid,
            Key = NewKey(),
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Theory]
    [InlineData("http://ap.example")]
    [InlineData("ap.example")]
    [InlineData("ftp://ap.example")]
    [InlineData("/relative/path")]
    public void Build_RejectsNonHttpsIssuer(string iss)
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = iss,
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = NewKey(),
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_RejectsNonHttpsPersonServer()
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = NewKey(),
            PersonServer = "http://ps.example",
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_EmitsRequiredHeaderClaims()
    {
        var key = NewKey();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = key,
        }.Build();

        var (header, _, _, _) = Decode(jwt);

        Assert.Equal("EdDSA", (string?)header["alg"]);
        Assert.Equal("aa-agent+jwt", (string?)header["typ"]);
        Assert.Equal("k1", (string?)header["kid"]);
    }

    [Fact]
    public void Build_EmitsRequiredPayloadClaims()
    {
        var key = NewKey();
        var iat = DateTimeOffset.FromUnixTimeSeconds(1_730_000_000);
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = key,
            IssuedAt = iat,
            Lifetime = TimeSpan.FromMinutes(30),
            TokenId = "jti-fixed",
        }.Build();

        var (_, payload, _, _) = Decode(jwt);

        Assert.Equal("https://ap.example", (string?)payload["iss"]);
        Assert.Equal("aauth-agent.json", (string?)payload["dwk"]);
        Assert.Equal("aauth:alice@ap.example", (string?)payload["sub"]);
        Assert.Equal("jti-fixed", (string?)payload["jti"]);
        Assert.Equal(iat.ToUnixTimeSeconds(), (long?)payload["iat"]);
        Assert.Equal(iat.ToUnixTimeSeconds() + 1800, (long?)payload["exp"]);

        var cnfJwk = payload["cnf"]!["jwk"]!.AsObject();
        Assert.Equal("OKP", (string?)cnfJwk["kty"]);
        Assert.Equal("Ed25519", (string?)cnfJwk["crv"]);
        Assert.Equal(Base64UrlEncoder.Encode(key.PublicKeyBytes), (string?)cnfJwk["x"]);
    }

    [Fact]
    public void Build_OptionalPsClaim()
    {
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = NewKey(),
            PersonServer = "https://ps.example",
        }.Build();

        var (_, payload, _, _) = Decode(jwt);
        Assert.Equal("https://ps.example", (string?)payload["ps"]);
    }

    [Fact(DisplayName = "§Sub-Agents — a sub-agent token emits parent_agent")]
    public void Build_EmitsParentAgent()
    {
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://vendor.example",
            Subject = "aauth:planner.7f3c+search1@vendor.example",
            KeyId = "k1",
            Key = NewKey(),
            ParentAgent = "aauth:planner.7f3c@vendor.example",
        }.Build();

        var (_, payload, _, _) = Decode(jwt);
        Assert.Equal("aauth:planner.7f3c@vendor.example", (string?)payload["parent_agent"]);
    }

    [Fact(DisplayName = "§Sub-Agents — a top-level token MUST NOT contain the '+' delimiter")]
    public void Build_RejectsPlusInTopLevelLocal()
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://vendor.example",
            Subject = "aauth:planner+oops@vendor.example",
            KeyId = "k1",
            Key = NewKey(),
            // No ParentAgent → top-level → '+' is illegal.
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact(DisplayName = "§Sub-Agents — single-level depth: a sub-agent's parent MUST be top-level")]
    public void Build_RejectsSubAgentOfSubAgent()
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://vendor.example",
            Subject = "aauth:planner.7f3c+search1+deep@vendor.example",
            KeyId = "k1",
            Key = NewKey(),
            ParentAgent = "aauth:planner.7f3c+search1@vendor.example", // parent is itself a sub-agent
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact(DisplayName = "§Sub-Agents — a sub-agent local part MUST derive from its parent_agent")]
    public void Build_RejectsMismatchedSubAgentParent()
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://vendor.example",
            Subject = "aauth:other+search1@vendor.example",
            KeyId = "k1",
            Key = NewKey(),
            ParentAgent = "aauth:planner.7f3c@vendor.example", // local part 'other' != 'planner.7f3c'
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_SignatureVerifiesWithEmbeddedPublicKey()
    {
        var key = NewKey();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = key,
        }.Build();

        var (_, payload, signature, signingInput) = Decode(jwt);

        var embeddedJwk = payload["cnf"]!["jwk"]!.AsObject();
        var publicKey = AAuthKey.FromJwk(embeddedJwk);

        Assert.True(publicKey.Verify(Encoding.ASCII.GetBytes(signingInput), signature));
    }

    [Fact]
    public void Build_RejectsPublicOnlyKey()
    {
        var publicOnly = AAuthKey.FromJwk(AAuthKey.Generate().ToPublicJwk());
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = publicOnly,
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_AdditionalClaim_CannotCollideWithRequired()
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = NewKey(),
            AdditionalClaims = new Dictionary<string, JsonNode?> { ["iss"] = "other" },
        };

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_AdditionalClaim_IsCopiedIntoPayload()
    {
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:alice@ap.example",
            KeyId = "k1",
            Key = NewKey(),
            AdditionalClaims = new Dictionary<string, JsonNode?> { ["scope"] = "data.read data.write" },
        }.Build();

        var (_, payload, _, _) = Decode(jwt);
        Assert.Equal("data.read data.write", (string?)payload["scope"]);
    }
}
