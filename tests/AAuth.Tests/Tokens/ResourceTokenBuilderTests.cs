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
    private static (string Jwt, JsonObject Payload) BuildSample(AAuthKey resourceKey)
    {
        var jwt = new ResourceTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            Agent = "aauth:demo@ap.example",
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
        Assert.Equal("aauth:demo@ap.example", (string?)payload["agent"]);
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
            Issuer = "https://r.example",
            Audience = "https://ps.example",
            Agent = "aauth:a@ap.example",
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
            Issuer = "http://r.example",
            Audience = "https://ps.example",
            Agent = "aauth:a@ap.example",
            AgentJkt = "t",
            Key = key,
            KeyId = "k",
        }.Build());
    }
}
