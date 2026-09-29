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
    public void EventWithJtiAndWithoutCnfVerifies()
    {
        var key = AAuthKey.Generate();
        var jwt = EventsTokens.Create(key, "resource", Payload(), false, Verifier);
        var token = EventsTokens.Verify(jwt, key, false, Verifier, "aauth:agent@ap.example");
        Assert.False(token.Payload.ContainsKey("cnf"));
        Assert.Equal("ev-4d2a91", token.Jti);
    }

    [Fact]
    public void EventWithoutJtiFails()
    {
        var key = AAuthKey.Generate();
        var payload = Payload();
        payload.Remove("jti");
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, false, Verifier));
    }

    [Fact]
    public void BuilderIssuesDistinctJtiPerEvent()
    {
        var key = AAuthKey.Generate();
        EventTokenBuilder Builder() => new()
        {
            Issuer = "https://resource.example", Audience = "aauth:agent@ap.example", Eid = "event-one",
            Key = key, KeyId = "resource", Verifier = Verifier,
        };
        var first = EventsTokens.Verify(Builder().Build(), key, false, Verifier);
        var second = EventsTokens.Verify(Builder().Build(), key, false, Verifier);
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
    public void InvalidEventClaimsFail(string claim, string json)
    {
        var key = AAuthKey.Generate();
        var payload = Payload();
        payload[claim] = JsonNode.Parse(json);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, false, Verifier));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void OldOrMismatchedAlgorithmsFail(string algorithm)
    {
        var key = AAuthKey.Generate();
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, Payload(), algorithm), key, false, Verifier));
    }

    private static JsonObject Payload() => new()
    {
        ["iss"] = "https://resource.example", ["dwk"] = EventsTokens.ResourceDwk,
        ["aud"] = "aauth:agent@ap.example", ["eid"] = "event-one", ["jti"] = "ev-4d2a91",
        ["iat"] = Now.ToUnixTimeSeconds(), ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds()
    };

    private static string Sign(IAAuthKey key, JsonObject payload, string algorithm = "Ed25519")
    {
        var header = new JsonObject { ["alg"] = algorithm, ["typ"] = EventsTokens.EventType, ["kid"] = "resource" };
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }
}