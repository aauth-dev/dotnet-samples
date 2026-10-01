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
    public async Task Build_PreservesOptionalAccount(string? account)
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
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes((await builder.BuildAsync()).Split('.')[1]))!.AsObject();
        Assert.Equal(account is not null, payload.ContainsKey("account"));
        Assert.Equal(account, (string?)payload["account"]);
    }

    private static async Task<(string Jwt, JsonObject Payload)> BuildSampleAsync(AAuthKey resourceKey)
    {
        var jwt = await new ResourceTokenBuilder
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
        }.BuildAsync();

        var payload = JsonNode.Parse(
            Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1])) as JsonObject;
        return (jwt, payload!);
    }

    [Fact]
    public async Task Build_EmitsRequiredClaims()
    {
        var key = AAuthKey.Generate();
        var (jwt, payload) = await BuildSampleAsync(key);

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
    public async Task Build_RejectsLifetimeOverFiveMinutes()
    {
        var key = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new ResourceTokenBuilder
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
        }.BuildAsync());
    }

    [Fact]
    public async Task Build_RejectsNonHttpsIssuer()
    {
        var key = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new ResourceTokenBuilder
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
        }.BuildAsync());
    }
}
