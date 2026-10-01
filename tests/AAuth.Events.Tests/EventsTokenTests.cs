using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Events.Tests;

public class EventsTokenTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1788880000);
    private static readonly TokenVerifier Verifier = new() { TimeProvider = new FakeTimeProvider(Now) };

    [Fact]
    public async Task EventWithJtiAndWithoutCnfVerifies()
    {
        var key = AAuthKey.Generate();
        var jwt = await EventsTokens.CreateAsync(key, "resource", Payload(), false, Verifier);
        var token = EventsTokens.Verify(jwt, key, false, Verifier, "aauth:agent@ap.example");
        Assert.False(token.Payload.ContainsKey("cnf"));
        Assert.Equal("ev-4d2a91", token.Jti);
    }

    [Fact]
    public async Task EventWithoutJtiFails()
    {
        var key = AAuthKey.Generate();
        var payload = Payload();
        payload.Remove("jti");
        var jwt = await SignAsync(key, payload);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(jwt, key, false, Verifier));
    }

    [Fact]
    public async Task BuilderIssuesDistinctJtiPerEvent()
    {
        var key = AAuthKey.Generate();
        EventTokenBuilder Builder() => new()
        {
            Issuer = "https://resource.example", Audience = "aauth:agent@ap.example", Eid = "event-one",
            Key = key, KeyId = "resource", Verifier = Verifier,
        };
        var first = EventsTokens.Verify(await Builder().BuildAsync(), key, false, Verifier);
        var second = EventsTokens.Verify(await Builder().BuildAsync(), key, false, Verifier);
        Assert.Equal((string?)first.Payload["eid"], (string?)second.Payload["eid"]);
        Assert.NotEqual(first.Jti, second.Jti);
    }

    [Theory]
    [InlineData("jti", "\"\"")]
    [InlineData("jti", "null")]
    [InlineData("cnf", "{}")]
    [InlineData("cnf", "null")]
    [InlineData("eid", "\"\"")]
    [InlineData("aud", "\"https://wrong.example\"")]
    [InlineData("dwk", "\"aauth-agent.json\"")]
    [InlineData("iat", "1788880001")]
    [InlineData("iat", "null")]
    [InlineData("exp", "1788880000")]
    public async Task InvalidEventClaimsFail(string claim, string json)
    {
        var key = AAuthKey.Generate();
        var payload = Payload();
        payload[claim] = JsonNode.Parse(json);
        var jwt = await SignAsync(key, payload);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(jwt, key, false, Verifier));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task OldOrMismatchedAlgorithmsFail(string algorithm)
    {
        var key = AAuthKey.Generate();
        var jwt = await SignAsync(key, Payload(), algorithm);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(jwt, key, false, Verifier));
    }

    private static JsonObject Payload() => new()
    {
        ["iss"] = "https://resource.example", ["dwk"] = EventsTokens.ResourceDwk,
        ["aud"] = "aauth:agent@ap.example", ["eid"] = "event-one", ["jti"] = "ev-4d2a91",
        ["iat"] = Now.ToUnixTimeSeconds(), ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds()
    };

    private static async Task<string> SignAsync(IAAuthSigner key, JsonObject payload, string algorithm = "Ed25519")
    {
        var header = new JsonObject { ["alg"] = algorithm, ["typ"] = EventsTokens.EventType, ["kid"] = "resource" };
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(await key.SignAsync(Encoding.ASCII.GetBytes(input)));
    }
}