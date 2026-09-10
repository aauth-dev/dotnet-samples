using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class AuthTokenBuilderTests
{
    [Theory]
    [InlineData(120, 3600, 120)]
    [InlineData(3600, 120, 120)]
    [InlineData(7200, 7200, 3600)]
    public void Build_BoundsAgentAndDelegationExpiry(int agentSeconds, int parentSeconds, int expectedSeconds)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var token = BoundedBuilder(now, now.AddSeconds(agentSeconds), now.AddSeconds(parentSeconds)).Build();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!;
        Assert.Equal(now.AddSeconds(expectedSeconds).ToUnixTimeSeconds(), (long)payload["exp"]!);
        Assert.Equal(now.ToUnixTimeSeconds(), (long)payload["iat"]!);
    }

    [Theory]
    [InlineData(0, 120)]
    [InlineData(-1, 120)]
    [InlineData(120, 0)]
    [InlineData(120, -1)]
    public void Build_RejectsExpiredAgentOrDelegation(int agentSeconds, int parentSeconds)
    {
        var now = DateTimeOffset.UtcNow;
        Assert.Throws<AuthTokenExpiredException>(() =>
            BoundedBuilder(now, now.AddSeconds(agentSeconds), now.AddSeconds(parentSeconds)).Build());
    }

    [Fact]
    public void Build_RejectsDefaultExpiry()
    {
        Assert.Throws<AuthTokenExpiredException>(() => BoundedBuilder(DateTimeOffset.UtcNow, default, null).Build());
    }

    [Fact]
    public void Build_AllowsIdentityExtensions()
    {
        var key = AAuthKey.Generate();
        var token = new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ps.example", Audience = "https://resource.example", Agent = "aauth:demo@ap.example",
            Key = key, KeyId = "ps1", AgentConfirmationKey = key, Scope = "read",
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            AdditionalClaims = new System.Collections.Generic.Dictionary<string, JsonNode?> { ["email"] = "user@example.test" },
        }.Build();
        Assert.Equal("user@example.test", (string?)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!["email"]);
    }

    private static AuthTokenBuilder BoundedBuilder(DateTimeOffset now, DateTimeOffset agentExpiry, DateTimeOffset? parentExpiry)
    {
        var key = AAuthKey.Generate();
        return new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ps.example", Audience = "https://resource.example", Agent = "aauth:demo@ap.example",
            Key = key, KeyId = "ps1", AgentConfirmationKey = key, Scope = "read", IssuedAt = now,
            AgentTokenExpiresAt = agentExpiry, AuthorizationExpiresAt = parentExpiry,
        };
    }

    [Theory]
    [InlineData("act")]
    [InlineData("mission")]
    [InlineData("account")]
    [InlineData("tenant")]
    [InlineData("roles")]
    [InlineData("groups")]
    [InlineData("sub")]
    [InlineData("nbf")]
    public void Build_RejectsUnsetReservedClaims(string claim)
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "ps1",
            Scope = "read",
            AdditionalClaims = new System.Collections.Generic.Dictionary<string, JsonNode?>
            {
                [claim] = "injected",
            },
        }.Build());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Build_RejectsNonPositiveLifetime(int seconds)
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "ps1",
            Scope = "read",
            Lifetime = TimeSpan.FromSeconds(seconds),
        }.Build());
    }

    [Fact]
    public void Build_EmitsRequiredClaims()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps1",
            Subject = "user-pairwise-id",
            Scope = "whoami",
        }.Build();

        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!;
        Assert.Equal("https://ps.example", (string?)payload["iss"]);
        Assert.Equal("aauth-person.json", (string?)payload["dwk"]);
        Assert.Equal("https://resource.example", (string?)payload["aud"]);
        Assert.Equal("aauth:demo@ap.example", (string?)payload["agent"]);
        Assert.Equal("user-pairwise-id", (string?)payload["sub"]);
        Assert.Equal("whoami", (string?)payload["scope"]);
        var cnfJwk = (JsonObject)payload["cnf"]!["jwk"]!;
        Assert.Equal(agentKey.ComputeJwkThumbprint(), AAuthKey.FromJwk(cnfJwk).ComputeJwkThumbprint());
        // act is OPTIONAL (§Delegation Chain) — a direct-auth token carries no act.
        Assert.Null(payload["act"]);
    }

    [Fact]
    public void Build_RejectsMissingSubAndScope()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "k",
        }.Build());
    }
}
