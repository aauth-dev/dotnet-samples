using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests.Tokens;

public sealed class EventsTokenTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void Subscribe_RoundTripsThroughCoreVerifier(string algorithm)
    {
        var key = CreateKey(algorithm);
        var confirmation = CreateKey(algorithm);
        var built = EventsTestData.Subscribe(key, confirmation, "eid-1", 2);
        var claims = SubscribeTokenClaims.Read(VerifySubscribe(built.Token, key));

        Assert.Equal("eid-1", built.Eid);
        Assert.Equal("eid-1", claims.Eid);
        Assert.Equal(2, claims.MaxUses);
        Assert.Equal(confirmation.ComputeJwkThumbprint(), claims.ConfirmationKey.ComputeJwkThumbprint());
        Assert.Equal("https", new Uri(claims.Issuer).Scheme);
        Assert.Equal("aauth:agent@ap.example", claims.Subject);
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void Event_RoundTripsAndHasNoConfirmationOrPayload(string algorithm)
    {
        var key = CreateKey(algorithm);
        var built = EventsTestData.Event(key, "jti-explicit");
        var verified = VerifyEvent(built.Token, key);
        var claims = EventTokenClaims.Read(verified);

        Assert.Equal("jti-explicit", claims.Jti);
        Assert.Null(verified.Payload[AAuthEventsConstants.ConfirmationClaim]);
        Assert.DoesNotContain("payload", verified.Payload.Select(p => p.Key));
    }

    [Fact]
    public void GeneratedIdentifiersAreBase64UrlAndUniqueForSameTimeInputs()
    {
        var key = AAuthKey.Generate();
        var one = EventsTestData.Subscribe(key);
        var two = EventsTestData.Subscribe(key);
        var e1 = EventsTestData.Event(key);
        var e2 = EventsTestData.Event(key);

        Assert.NotEqual(one.Eid, two.Eid);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(one.Eid).Length);
        Assert.NotEqual(e1.Jti, e2.Jti);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(e1.Jti).Length);
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
    public void EventHeaderAndPayloadHaveExactRequiredFoundation()
    {
        var token = EventsTestData.Event(AAuthKey.Generate()).Token;
        var (header, payload) = Decode(token);

        Assert.Equal(new[] { "alg", "typ", "kid" }, header.Select(p => p.Key));
        Assert.Equal(
            new[] { "iss", "dwk", "aud", "eid", "iat", "exp", "jti" },
            payload.Select(p => p.Key));
    }

    [Fact]
    public void SubscribeHeaderAndPayloadHaveExactRequiredFoundation()
    {
        var key = AAuthKey.Generate();
        var withoutLimit = Decode(EventsTestData.Subscribe(key).Token);
        var withLimit = Decode(EventsTestData.Subscribe(key, maxUses: 2).Token);

        Assert.Equal(new[] { "alg", "typ", "kid" }, withoutLimit.Header.Select(p => p.Key));
        Assert.Equal(
            new[] { "iss", "dwk", "sub", "aud", "cnf", "eid", "iat", "exp" },
            withoutLimit.Payload.Select(p => p.Key));
        Assert.Equal(
            new[] { "iss", "dwk", "sub", "aud", "cnf", "eid", "iat", "exp", "max_uses" },
            withLimit.Payload.Select(p => p.Key));
        Assert.IsType<JsonObject>(withoutLimit.Payload["cnf"]?["jwk"]);
    }

    [Fact]
    public void BuildersRejectInvalidConfiguration()
    {
        var privateKey = AAuthKey.Generate();
        var publicKey = AAuthKey.FromJwk(privateKey.ToPublicJwk());
        var confirmation = AAuthKey.Generate();

        Assert.Throws<InvalidOperationException>(() => EventsTestData.Event(publicKey).Token);
        Assert.Throws<InvalidOperationException>(() => BuildEvent(
            privateKey, issuer: "http://not-loopback.example"));
        Assert.Throws<InvalidOperationException>(() => BuildEvent(
            privateKey, audience: "not-an-agent"));
        Assert.Throws<InvalidOperationException>(() => BuildEvent(
            privateKey, lifetime: TimeSpan.FromMilliseconds(500)));
        Assert.Throws<InvalidOperationException>(() => BuildEvent(
            privateKey, jti: " "));
        Assert.Throws<InvalidOperationException>(() => new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:agent@ap.example",
            Eid = "eid",
            KeyId = "kid",
            Key = new UnsupportedKey("none"),
        }.Build());

        Assert.Throws<InvalidOperationException>(() => BuildSubscribe(
            privateKey, confirmation, issuer: "http://not-loopback.example"));
        Assert.Throws<InvalidOperationException>(() => BuildSubscribe(
            privateKey, confirmation, subject: "not-an-agent"));
        Assert.Throws<InvalidOperationException>(() => BuildSubscribe(
            privateKey, confirmation, lifetime: TimeSpan.Zero));
        Assert.Throws<InvalidOperationException>(() => BuildSubscribe(
            privateKey, confirmation, maxUses: 0));
        Assert.Throws<InvalidOperationException>(() => BuildSubscribe(
            privateKey, confirmation, eid: " "));
        Assert.Throws<InvalidOperationException>(() => new SubscribeTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Audience = "https://resource.example",
            KeyId = "kid",
            Key = privateKey,
            ConfirmationKey = null!,
        }.Build());
    }

    [Fact]
    public void BuildersAcceptLoopbackHttp()
    {
        var key = AAuthKey.Generate();
        var confirmation = AAuthKey.Generate();

        var subscribe = BuildSubscribe(
            key, confirmation, issuer: "http://localhost:5301", audience: "http://127.0.0.1:5005");
        var eventToken = BuildEvent(key, issuer: "http://[::1]:5005");

        Assert.NotEmpty(subscribe.Token);
        Assert.NotEmpty(eventToken.Token);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("RS256")]
    [InlineData("")]
    public void ClaimReadersRejectUnsupportedAlgorithms(string algorithm)
    {
        var key = AAuthKey.Generate();
        var subscribe = VerifySubscribe(EventsTestData.Subscribe(key).Token, key);
        var eventToken = VerifyEvent(EventsTestData.Event(key).Token, key);
        subscribe.Header["alg"] = algorithm;
        eventToken.Header["alg"] = algorithm;

        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(subscribe));
        Assert.Throws<TokenVerificationException>(() => EventTokenClaims.Read(eventToken));
    }

    [Fact]
    public void SubscribeClaimsRejectMissingOrInvalidRequiredValues()
    {
        var key = AAuthKey.Generate();
        var valid = VerifySubscribe(EventsTestData.Subscribe(key, maxUses: 2).Token, key);
        var cases = new Action<JsonObject, JsonObject>[]
        {
            static (header, _) => header.Remove("kid"),
            static (_, payload) => payload.Remove("iat"),
            static (_, payload) => payload.Remove("exp"),
            static (_, payload) => payload.Remove("eid"),
            static (_, payload) => payload["eid"] = " ",
            static (_, payload) => payload.Remove("sub"),
            static (_, payload) => payload["sub"] = "not-an-agent",
            static (_, payload) => payload.Remove("aud"),
            static (_, payload) => payload["aud"] = "not-a-url",
            static (_, payload) => payload.Remove("iss"),
            static (_, payload) => payload.Remove("cnf"),
            static (_, payload) => payload["max_uses"] = 0,
            static (_, payload) => payload["max_uses"] = "one",
            static (_, payload) => payload["exp"] = payload["iat"]!.GetValue<long>(),
        };

        foreach (var mutate in cases)
        {
            var candidate = Clone(valid);
            mutate(candidate.Header, candidate.Payload);
            Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(candidate));
        }
    }

    [Fact]
    public void EventClaimsRejectMissingOrInvalidRequiredValues()
    {
        var key = AAuthKey.Generate();
        var valid = VerifyEvent(EventsTestData.Event(key).Token, key);
        var cases = new Action<JsonObject, JsonObject>[]
        {
            static (header, _) => header.Remove("kid"),
            static (_, payload) => payload.Remove("iat"),
            static (_, payload) => payload.Remove("exp"),
            static (_, payload) => payload.Remove("jti"),
            static (_, payload) => payload["jti"] = " ",
            static (_, payload) => payload.Remove("eid"),
            static (_, payload) => payload["eid"] = " ",
            static (_, payload) => payload.Remove("aud"),
            static (_, payload) => payload["aud"] = "not-an-agent",
            static (_, payload) => payload.Remove("iss"),
            static (_, payload) => payload["exp"] = payload["iat"]!.GetValue<long>(),
        };

        foreach (var mutate in cases)
        {
            var candidate = Clone(valid);
            mutate(candidate.Header, candidate.Payload);
            Assert.Throws<TokenVerificationException>(() => EventTokenClaims.Read(candidate));
        }
    }

    [Fact]
    public void ClaimReadersRejectWrongTypeAndDwk()
    {
        var key = AAuthKey.Generate();
        var subscribe = VerifySubscribe(EventsTestData.Subscribe(key).Token, key);
        var eventToken = VerifyEvent(EventsTestData.Event(key).Token, key);

        subscribe.Header["typ"] = AAuthEventsConstants.EventTokenType;
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(subscribe));

        eventToken.Payload["dwk"] = AAuthEventsConstants.AgentDwk;
        Assert.Throws<TokenVerificationException>(() => EventTokenClaims.Read(eventToken));
    }

    [Fact]
    public void TamperingFailsCoreVerification()
    {
        var key = AAuthKey.Generate();
        var built = EventsTestData.Event(key);
        var parts = built.Token.Split('.');
        parts[1] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(
            """{"iss":"https://resource.example","dwk":"aauth-resource.json","aud":"aauth:agent@ap.example","eid":"event-1","iat":1750000000,"exp":1750000300,"jti":"changed"}"""));
        var tampered = string.Join(".", parts);

        Assert.Throws<TokenVerificationException>(() => VerifyEvent(tampered, key));
    }

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();

    private static SubscribeTokenArtifact BuildSubscribe(
        IAAuthKey key,
        IAAuthKey confirmationKey,
        string issuer = "https://ap.example",
        string subject = "aauth:agent@ap.example",
        string audience = "https://resource.example",
        TimeSpan? lifetime = null,
        long? maxUses = null,
        string? eid = null) =>
        new SubscribeTokenBuilder
        {
            Issuer = issuer,
            Subject = subject,
            Audience = audience,
            KeyId = "ap-1",
            Key = key,
            ConfirmationKey = confirmationKey,
            IssuedAt = EventsTestData.Now,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
            EventId = eid,
            MaxUses = maxUses,
        }.Build();

    private static EventTokenArtifact BuildEvent(
        IAAuthKey key,
        string issuer = "https://resource.example",
        string audience = "aauth:agent@ap.example",
        TimeSpan? lifetime = null,
        string? jti = null) =>
        new EventTokenBuilder
        {
            Issuer = issuer,
            Audience = audience,
            Eid = "event-1",
            KeyId = "resource-1",
            Key = key,
            IssuedAt = EventsTestData.Now,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
            Jti = jti,
        }.Build();

    private static TokenVerifier.VerifiedToken VerifySubscribe(string token, IAAuthKey key) =>
        new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(token, key, AAuthEventsConstants.SubscribeTokenType,
                AAuthEventsConstants.AgentDwk, "https://resource.example");

    private static TokenVerifier.VerifiedToken VerifyEvent(string token, IAAuthKey key) =>
        new TokenVerifier { Clock = () => EventsTestData.Now }
            .Verify(token, key, AAuthEventsConstants.EventTokenType,
                AAuthEventsConstants.ResourceDwk, "aauth:agent@ap.example");

    private static (JsonObject Header, JsonObject Payload) Decode(string token) =>
        (
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]))!.AsObject(),
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject()
        );

    private static TokenVerifier.VerifiedToken Clone(TokenVerifier.VerifiedToken token) =>
        new(
            (JsonObject)token.Header.DeepClone(),
            (JsonObject)token.Payload.DeepClone(),
            token.Issuer,
            token.TokenType);

    private sealed class UnsupportedKey(string algorithm) : IAAuthKey
    {
        public string Algorithm { get; } = algorithm;
        public bool HasPrivateKey => true;
        public byte[] Sign(byte[] data) => throw new NotSupportedException();
        public bool Verify(byte[] data, byte[] signature) => false;
        public JsonObject ToPublicJwk() => [];
        public JsonObject ToPrivateJwk() => [];
        public string ComputeJwkThumbprint() => string.Empty;
    }
}
