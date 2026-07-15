using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using AAuth.Events.Tests.TestSupport;

namespace AAuth.Events.Tests.Tokens;

public sealed class EventsTokenTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void Subscribe_RoundTripsThroughCoreVerifier(string algorithm)
    {
        IAAuthKey key = algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();
        var confirmation = AAuthKey.Generate();
        var built = EventsTestData.Subscribe(key, confirmation, "eid-1", 2);
        var verified = new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(built.Token, key, AAuthEventsConstants.SubscribeTokenType,
                AAuthEventsConstants.AgentDwk, "https://resource.example");
        var claims = SubscribeTokenClaims.Read(verified);

        Assert.Equal("eid-1", built.Eid);
        Assert.Equal("eid-1", claims.Eid);
        Assert.Equal(2, claims.MaxUses);
        Assert.Equal(confirmation.ComputeJwkThumbprint(), claims.ConfirmationKey.ComputeJwkThumbprint());
        Assert.Equal("https", new Uri(claims.Issuer).Scheme);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void Event_RoundTripsAndHasNoConfirmationOrPayload(string algorithm)
    {
        IAAuthKey key = algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();
        var built = EventsTestData.Event(key, "jti-explicit");
        var verified = new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(built.Token, key, AAuthEventsConstants.EventTokenType,
                AAuthEventsConstants.ResourceDwk, "aauth:agent@ap.example");
        var claims = EventTokenClaims.Read(verified);

        Assert.Equal("jti-explicit", claims.Jti);
        Assert.Null(verified.Payload[AAuthEventsConstants.ConfirmationClaim]);
        Assert.DoesNotContain("payload", verified.Payload.Select(p => p.Key));
    }

    [Fact]
    public void GeneratedIdentifiersAreBase64UrlAndUnique()
    {
        var key = AAuthKey.Generate();
        var one = EventsTestData.Subscribe(key);
        var two = EventsTestData.Subscribe(key);
        var e1 = EventsTestData.Event(key);
        var e2 = EventsTestData.Event(key);

        Assert.NotEqual(one.Eid, two.Eid);
        Assert.InRange(Base64UrlEncoder.DecodeBytes(one.Eid).Length, 16, int.MaxValue);
        Assert.NotEqual(e1.Jti, e2.Jti);
        Assert.InRange(Base64UrlEncoder.DecodeBytes(e1.Jti).Length, 16, int.MaxValue);
        Assert.NotEqual(e1.Token, e2.Token);
    }

    [Fact]
    public void ExplicitIdentifiersArePreserved()
    {
        var key = AAuthKey.Generate();
        Assert.Equal("stable", EventsTestData.Subscribe(key, eid: "stable").Eid);
        Assert.Equal("event-jti", EventsTestData.Event(key, "event-jti").Jti);
    }

    [Fact]
    public void HeaderAndPayloadHaveExactRequiredFoundation()
    {
        var key = AAuthKey.Generate();
        var token = EventsTestData.Event(key).Token;
        var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject();

        Assert.Equal(new[] { "alg", "typ", "kid" }, header.Select(p => p.Key));
        Assert.Equal(new[] { "iss", "dwk", "aud", "eid", "iat", "exp", "jti" }, payload.Select(p => p.Key));
    }

    [Fact]
    public void BuildersRejectInvalidConfiguration()
    {
        var privateKey = AAuthKey.Generate();
        var publicKey = AAuthKey.FromJwk(privateKey.ToPublicJwk());
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() => EventsTestData.Event(publicKey).Token);
        Assert.Throws<InvalidOperationException>(() => new EventTokenBuilder
        {
            Issuer = "http://not-loopback.example",
            Audience = "agent",
            Eid = "eid",
            KeyId = "kid",
            Key = key,
        }.Build());
        Assert.Throws<InvalidOperationException>(() => new SubscribeTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "agent",
            Audience = "https://resource.example",
            KeyId = "kid",
            Key = key,
            Lifetime = TimeSpan.Zero,
        }.Build());
        Assert.Throws<InvalidOperationException>(() => new SubscribeTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "agent",
            Audience = "https://resource.example",
            KeyId = "kid",
            Key = key,
            MaxUses = 0,
        }.Build());
    }

    [Fact]
    public void ClaimsRejectMissingJtiAndInvalidTimes()
    {
        var key = AAuthKey.Generate();
        var built = EventsTestData.Event(key);
        var verified = new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(built.Token, key, AAuthEventsConstants.EventTokenType,
                AAuthEventsConstants.ResourceDwk, "aauth:agent@ap.example");
        verified.Payload.Remove(AAuthEventsConstants.TokenIdClaim);
        Assert.Throws<TokenVerificationException>(() => EventTokenClaims.Read(verified));
    }

    [Fact]
    public void TamperingFailsCoreVerification()
    {
        var key = AAuthKey.Generate();
        var built = EventsTestData.Event(key);
        var parts = built.Token.Split('.');
        parts[1] = Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(
            """{"iss":"https://resource.example","dwk":"aauth-resource.json","aud":"aauth:agent@ap.example","eid":"event-1","iat":1750000000,"exp":1750000300,"jti":"changed"}"""));
        var tampered = string.Join(".", parts);
        Assert.Throws<TokenVerificationException>(() => new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(tampered, key, AAuthEventsConstants.EventTokenType,
                AAuthEventsConstants.ResourceDwk, "aauth:agent@ap.example"));
    }
}
