using System.Buffers.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;

namespace AAuth.R3.Tests;

public class R3ChallengeTimeTests
{
    [Fact(DisplayName = "R3Challenge stamps iat and exp from its TimeProvider")]
    public async Task ResourceToken_UsesTimeProvider()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var challenge = new R3Challenge
        {
            ResourceIssuer = R3TestData.ResourceIssuer,
            Audience = R3TestData.AsIssuer,
            Key = AAuthKey.Generate(),
            KeyId = R3TestData.ResourceKid,
            TimeProvider = new FakeTimeProvider(now),
            OperationValidator = NoopOperationValidator.Instance,
        };
        var presented = new TokenVerifier.VerifiedToken(new JsonObject(), new JsonObject
        {
            ["sub"] = "person-1",
            ["jti"] = "person-token-1",
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
        }, R3TestData.PsIssuer, PersonTokenBuilder.TokenType);

        var token = await challenge.BuildResourceTokenAsync(presented, agentJkt: "agent-jkt",
            r3Uri: R3TestData.ResourceIssuer + "/r3/doc", r3S256: R3Hash.ComputeS256("{}"u8), scope: null);

        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(token.Split('.')[1]))!;
        Assert.Equal(now.ToUnixTimeSeconds(), (long)payload["iat"]!);
        Assert.Equal(now.Add(challenge.Lifetime).ToUnixTimeSeconds(), (long)payload["exp"]!);
    }
}
