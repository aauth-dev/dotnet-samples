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
    public async Task Build_BoundsAgentAndDelegationExpiry(int agentSeconds, int parentSeconds, int expectedSeconds)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var token = await BoundedBuilder(now, now.AddSeconds(agentSeconds), now.AddSeconds(parentSeconds)).BuildAsync();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!;
        Assert.Equal(now.AddSeconds(expectedSeconds).ToUnixTimeSeconds(), (long)payload["exp"]!);
        Assert.Equal(now.ToUnixTimeSeconds(), (long)payload["iat"]!);
    }

    [Theory]
    [InlineData(0, 120)]
    [InlineData(-1, 120)]
    [InlineData(120, 0)]
    [InlineData(120, -1)]
    public async Task Build_RejectsExpiredAgentOrDelegation(int agentSeconds, int parentSeconds)
    {
        var now = DateTimeOffset.UtcNow;
        await Assert.ThrowsAsync<AuthTokenExpiredException>(async () =>
            await BoundedBuilder(now, now.AddSeconds(agentSeconds), now.AddSeconds(parentSeconds)).BuildAsync());
    }

    [Fact]
    public async Task Build_RejectsDefaultExpiry()
    {
        await Assert.ThrowsAsync<AuthTokenExpiredException>(async () => await BoundedBuilder(DateTimeOffset.UtcNow, default, null).BuildAsync());
    }

    [Fact]
    public async Task Build_AllowsIdentityExtensions()
    {
        var key = AAuthKey.Generate();
        var token = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ps.example", Audience = "https://resource.example", PersonServer = "https://ps.example", Subject = "person-1",
            Key = key, KeyId = "ps1", AgentConfirmationKey = key, Scope = "read",
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            AdditionalClaims = new System.Collections.Generic.Dictionary<string, JsonNode?> { ["email"] = "user@example.test" },
        }.BuildAsync();
        Assert.Equal("user@example.test", (string?)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!["email"]);
    }

    private static AuthTokenBuilder BoundedBuilder(DateTimeOffset now, DateTimeOffset agentExpiry, DateTimeOffset? parentExpiry)
    {
        var key = AAuthKey.Generate();
        return new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ps.example", Audience = "https://resource.example", PersonServer = "https://ps.example", Subject = "person-1",
            Key = key, KeyId = "ps1", AgentConfirmationKey = key, Scope = "read", IssuedAt = now,
            AgentTokenExpiresAt = agentExpiry, AuthorizationExpiresAt = parentExpiry,
        };
    }

    [Theory]
    [InlineData("act")]
    [InlineData("mission")]
    [InlineData("agent")]
    [InlineData("mission_s256")]
    [InlineData("ps")]
    [InlineData("account")]
    [InlineData("tenant")]
    [InlineData("roles")]
    [InlineData("groups")]
    [InlineData("sub")]
    [InlineData("nbf")]
    public async Task Build_RejectsUnsetReservedClaims(string claim)
    {
        var key = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "ps1",
            Scope = "read",
            AdditionalClaims = new System.Collections.Generic.Dictionary<string, JsonNode?>
            {
                [claim] = "injected",
            },
        }.BuildAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Build_RejectsNonPositiveLifetime(int seconds)
    {
        var key = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "ps1",
            Scope = "read",
            Lifetime = TimeSpan.FromSeconds(seconds),
        }.BuildAsync());
    }

    [Fact]
    public async Task Build_EmitsRequiredClaims()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            PersonServer = "https://ps.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps1",
            Subject = "user-pairwise-id",
            Scope = "whoami",
        }.BuildAsync();

        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!;
        Assert.Equal("https://ps.example", (string?)payload["iss"]);
        Assert.Equal("aauth-person.json", (string?)payload["dwk"]);
        Assert.Equal("https://resource.example", (string?)payload["aud"]);
        Assert.Equal("https://ps.example", (string?)payload["ps"]);
        Assert.Equal("user-pairwise-id", (string?)payload["sub"]);
        Assert.Equal("whoami", (string?)payload["scope"]);
        var cnfJwk = (JsonObject)payload["cnf"]!["jwk"]!;
        Assert.Equal(agentKey.ComputeJwkThumbprint(), AAuthKey.FromJwk(cnfJwk).ComputeJwkThumbprint());
        // §Auth Token Structure: no agent identifier and no delegation chain.
        Assert.Null(payload["agent"]);
        Assert.Null(payload["act"]);
    }

    [Theory]
    [InlineData("", "https://ps.example")]
    [InlineData("person-1", "")]
    public async Task Build_RejectsMissingSubOrPersonServer(string subject, string personServer)
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            PersonServer = personServer,
            Subject = subject,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "k",
        }.BuildAsync());
    }

    [Theory]
    [InlineData("not-a-dwk", "https://ps.example")]
    [InlineData(AuthTokenBuilder.PersonDwk, "https://other-ps.example")]
    public async Task Build_RejectsInvalidDwkAndMismatchedPsIssuer(string dwk, string personServer)
    {
        var key = AAuthKey.Generate();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            PersonServer = personServer,
            Subject = "person-1",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "k",
            Dwk = dwk,
        }.BuildAsync());
    }

    [Fact]
    public async Task Build_AllowsAccessDwkForFederatedAsIssuer()
    {
        var key = AAuthKey.Generate();
        var jwt = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://as.example",
            Audience = "https://resource.example",
            PersonServer = "https://ps.example",
            Subject = "person-1",
            AgentConfirmationKey = key,
            Key = key,
            KeyId = "k",
            Dwk = AuthTokenBuilder.AccessDwk,
        }.BuildAsync();
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!;
        Assert.Equal(AuthTokenBuilder.AccessDwk, (string?)payload["dwk"]);
        Assert.Equal("https://ps.example", (string?)payload["ps"]);
    }
}
