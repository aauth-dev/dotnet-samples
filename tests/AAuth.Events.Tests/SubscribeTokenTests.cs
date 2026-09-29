using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests;

public class SubscribeTokenTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static readonly TokenVerifier Verifier = new() { TimeProvider = new FakeTimeProvider(Now) };

    [Theory]
    [InlineData("https://evil.example", "aauth:victim@ap.example", false)]
    [InlineData("https://ap.example.evil.example", "aauth:victim@ap.example", false)]
    [InlineData("https://ap.example", "aauth:victim@ap.example/path", false)]
    [InlineData("https://ap.example", "aauth:victim@ap.example", true)]
    [InlineData("http://127.0.0.1:5301", "aauth:victim@127.0.0.1", true)]
    [InlineData("http://127.0.0.1:5301", "aauth:victim@localhost", false)]
    [InlineData("http://127.0.0.1:5301", "aauth:victim@ap.example", false)]
    public void SubscribeIssuerMustOwnAgentDomain(string issuer, string subject, bool valid)
    {
        var key = AAuthKey.Generate();
        var payload = Payload(key);
        payload["iss"] = issuer;
        payload["sub"] = subject;
        var verifier = new TokenVerifier { TimeProvider = new FakeTimeProvider(Now),
            EgressPolicy = new AAuth.Discovery.AAuthEgressPolicy(["http://127.0.0.1:5301"]) };
        if (valid) EventsTokens.Verify(Sign(key, payload), key, true, verifier);
        else Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, true, verifier));
    }

    [Theory]
    [InlineData("max_uses", "0")]
    [InlineData("max_uses", "-1")]
    [InlineData("max_uses", "1.5")]
    [InlineData("max_uses", "\"1\"")]
    [InlineData("max_uses", "null")]
    [InlineData("eid", "null")]
    [InlineData("eid", "\"\"")]
    [InlineData("iat", "null")]
    [InlineData("sub", "\"not-an-agent\"")]
    [InlineData("aud", "[]")]
    [InlineData("cnf", "{}")]
    [InlineData("cnf", "null")]
    [InlineData("dwk", "\"aauth-resource.json\"")]
    [InlineData("iss", "\"not-a-url\"")]
    public void InvalidSubscribeClaimsFail(string name, string json)
    {
        var key = AAuthKey.Generate();
        var payload = Payload(key);
        payload[name] = JsonNode.Parse(json);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, true, Verifier));
    }

    [Theory]
    [InlineData("exp")]
    [InlineData("iat")]
    [InlineData("eid")]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("cnf")]
    [InlineData("dwk")]
    [InlineData("iss")]
    public void MissingRequiredClaimFails(string claim)
    {
        var key = AAuthKey.Generate();
        var payload = Payload(key); payload.Remove(claim);
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, true, Verifier));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothAlgorithmsSupportBoundedAndUnlimitedWithoutJti(bool ecdsa)
    {
        IAAuthKey key = ecdsa ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();
        var jwt = new SubscribeTokenBuilder { Issuer = "https://ap.example", Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example", Eid = "eid", Key = key, KeyId = "key", ConfirmationKey = key, Verifier = Verifier }.Build();
        var verified = EventsTokens.Verify(jwt, key, true, Verifier, "https://resource.example");
        Assert.False(verified.Payload.ContainsKey("max_uses"));
        Assert.False(verified.Payload.ContainsKey("jti"));
        var payload = Payload(key); payload["max_uses"] = 2; payload["jti"] = "optional";
        Assert.Equal(2, EventsTokens.Verify(Sign(key, payload), key, true, Verifier).Payload["max_uses"]!.GetValue<int>());
        var eventJwt = new EventTokenBuilder { Issuer = "https://resource.example", Audience = "aauth:agent@ap.example", Eid = "eid",
            Key = key, KeyId = "key", Verifier = Verifier }.Build();
        Assert.Equal(EventsTokens.EventType, EventsTokens.Verify(eventJwt, key, false, Verifier).TokenType);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("none")]
    [InlineData("")]
    public void ConfirmationKeyRequiresCurrentPublicAlgorithm(string algorithm)
    {
        var key = AAuthKey.Generate(); var payload = Payload(key);
        payload["cnf"]!["jwk"]!["alg"] = algorithm;
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, true, Verifier));
    }

    [Theory]
    [InlineData("exp", -1)]
    [InlineData("iat", 60)]
    public void ExpiredOrFutureSubscribeFails(string claim, int offset)
    {
        var key = AAuthKey.Generate(); var payload = Payload(key);
        payload[claim] = Now.AddSeconds(offset).ToUnixTimeSeconds();
        Assert.Throws<TokenVerificationException>(() => EventsTokens.Verify(Sign(key, payload), key, true, Verifier));
    }

    private static JsonObject Payload(IAAuthKey key) => new()
    {
        ["iss"] = "https://ap.example", ["dwk"] = EventsTokens.AgentDwk, ["sub"] = "aauth:agent@ap.example",
        ["aud"] = "https://resource.example", ["eid"] = "eid", ["cnf"] = new JsonObject { ["jwk"] = key.ToPublicJwk() },
        ["iat"] = Now.ToUnixTimeSeconds(), ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds()
    };

    private static string Sign(IAAuthKey key, JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = EventsTokens.SubscribeType, ["kid"] = "key" };
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }
}