using System;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class ResourceTokenBuilderTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("workspace/Personal")]
    [InlineData("workspace/personal")]
    public void Build_PreservesOptionalAccount(string? account)
    {
        var builder = new ResourceTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "thumbprint-here",
            Key = AAuthKey.Generate(),
            KeyId = "r1",
            Account = account,
        };
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(builder.Build().Split('.')[1]))!.AsObject();
        Assert.Equal(account is not null, payload.ContainsKey("account"));
        Assert.Equal(account, (string?)payload["account"]);
    }

    private static (string Jwt, JsonObject Payload) BuildSample(AAuthKey resourceKey)
    {
        var jwt = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "thumbprint-here",
            Key = resourceKey,
            KeyId = "r1",
            Scope = "whoami",
        }.Build();

        var payload = JsonNode.Parse(
            Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1])) as JsonObject;
        return (jwt, payload!);
    }

    [Fact]
    public void Build_EmitsRequiredClaims()
    {
        var key = AAuthKey.Generate();
        var (jwt, payload) = BuildSample(key);

        Assert.Equal("https://resource.example", (string?)payload["iss"]);
        Assert.Equal("aauth-resource.json", (string?)payload["dwk"]);
        Assert.Equal("https://ps.example", (string?)payload["aud"]);
        Assert.Equal("https://ps.example", (string?)payload["ps"]);
        Assert.Equal("person-1", (string?)payload["sub"]);
        Assert.Equal("person-token-1", (string?)payload["presented_jti"]);
        Assert.Null(payload["agent"]);
        Assert.Equal("thumbprint-here", (string?)payload["agent_jkt"]);
        Assert.Equal("whoami", (string?)payload["scope"]);
        Assert.NotNull(payload["jti"]);
        Assert.NotNull(payload["iat"]);
        Assert.NotNull(payload["exp"]);
    }

    [Fact]
    public void Build_RejectsLifetimeOverFiveMinutes()
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://r.example",
            Audience = "https://ps.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "thumb",
            Key = key,
            KeyId = "k",
            Lifetime = TimeSpan.FromMinutes(10),
        }.Build());
    }

    [Fact]
    public void Build_RejectsNonHttpsIssuer()
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "http://r.example",
            Audience = "https://ps.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "t",
            Key = key,
            KeyId = "k",
        }.Build());
    }
}
