using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class AuthTokenBuilderTests
{
    [Fact]
    public void Build_EmitsRequiredClaims()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
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
            Issuer = "https://ps.example",
            Audience = "https://resource.example",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "k",
        }.Build());
    }
}
