using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests.Conformance;

public sealed class SubscribeTokenConformanceTests
{
    private const string Issuer = "https://ap.example";
    private const string Subject = "aauth:agent@ap.example";
    private const string Audience = "https://resource.example";
    private const string Kid = "ap-1";

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    [Trait("Spec", "Events §Subscribe Token L204-L280; C21")]
    public void IssuanceHasExactTypeDomainAndRequiredClaims(string algorithm)
    {
        var signingKey = CreateKey(algorithm);
        var confirmationKey = CreateKey(algorithm);
        var token = Build(signingKey, confirmationKey, eid: "eid-1").Token;
        var (header, payload) = Decode(token);

        Assert.Equal(AAuthEventsConstants.SubscribeTokenType, header["typ"]!.GetValue<string>());
        Assert.Equal(signingKey.Algorithm, header["alg"]!.GetValue<string>());
        Assert.Equal(Kid, header["kid"]!.GetValue<string>());
        Assert.Equal(Issuer, payload["iss"]!.GetValue<string>());
        Assert.Equal(AAuthEventsConstants.AgentDwk, payload["dwk"]!.GetValue<string>());
        Assert.Equal(Subject, payload["sub"]!.GetValue<string>());
        Assert.Equal(Audience, payload["aud"]!.GetValue<string>());
        Assert.Equal("eid-1", payload["eid"]!.GetValue<string>());
        Assert.Equal(1_750_000_000, payload["iat"]!.GetValue<long>());
        Assert.Equal(1_750_000_300, payload["exp"]!.GetValue<long>());
        Assert.Null(payload["max_uses"]);
        Assert.NotNull(payload["cnf"]?["jwk"]);
        Assert.Equal(
            confirmationKey.ComputeJwkThumbprint(),
            KeyFactory.FromJwk(payload["cnf"]!["jwk"]!.AsObject()).ComputeJwkThumbprint());
    }

    [Theory]
    [InlineData(null)]
    [InlineData(1L)]
    [InlineData(100L)]
    [Trait("Spec", "Events §Subscribe Token L224-L244; C16")]
    public void MaxUsesIsOptionalAndPreservedWhenPositive(long? maxUses)
    {
        var key = AAuthKey.Generate();
        var token = Build(key, AAuthKey.Generate(), maxUses: maxUses).Token;
        var verified = Verify(token, key);
        var claims = SubscribeTokenClaims.Read(verified);

        Assert.Equal(maxUses, claims.MaxUses);
        if (maxUses is null)
            Assert.False(verified.Payload.ContainsKey(AAuthEventsConstants.MaxUsesClaim));
        else
            Assert.Equal(maxUses, verified.Payload["max_uses"]!.GetValue<long>());
    }

    [Theory]
    [InlineData("none")]
    [InlineData("RS256")]
    [InlineData("")]
    [Trait("Spec", "Events §Subscribe Token Structure/Verification L209-L227; C21")]
    public void NoneUnsupportedAndMissingAlgorithmsAreRejected(string algorithm)
    {
        var key = AAuthKey.Generate();
        var original = Build(key, AAuthKey.Generate()).Token;
        var token = RewriteAndResign(original, key,
            (header, _) =>
            {
                if (algorithm.Length == 0)
                    header.Remove("alg");
                else
                    header["alg"] = algorithm;
            });

        Assert.Throws<TokenVerificationException>(() => Verify(token, key));
        var verified = DecodeVerified(original, key);
        if (algorithm.Length == 0)
            verified.Header.Remove("alg");
        else
            verified.Header["alg"] = algorithm;
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(verified));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269")]
    public void WrongTypeAndDomainKeyAreRejectedByReader()
    {
        var key = AAuthKey.Generate();
        var token = Build(key, AAuthKey.Generate()).Token;

        var wrongType = DecodeVerified(token, key);
        wrongType.Header["typ"] = AAuthEventsConstants.EventTokenType;
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(wrongType));

        var wrongDwk = DecodeVerified(token, key);
        wrongDwk.Payload["dwk"] = AAuthEventsConstants.ResourceDwk;
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(wrongDwk));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269")]
    public void SignaturePayloadTamperingFailsCoreVerification()
    {
        var key = AAuthKey.Generate();
        var parts = Build(key, AAuthKey.Generate(), eid: "original").Token.Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1]))!.AsObject();
        payload["eid"] = "tampered";
        parts[1] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));

        Assert.Throws<TokenVerificationException>(() => Verify(string.Join('.', parts), key));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269")]
    public async Task MissingAndWrongKidAreRejectedDuringJwksResolution()
    {
        var key = AAuthKey.Generate();
        var resolver = CreateResolver(key, Kid);
        var token = Build(key, AAuthKey.Generate()).Token;

        var missingKid = RewriteAndResign(token, key, (header, _) => header.Remove("kid"));
        var missingError = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveSubscribeAsync(missingKid, Audience));
        Assert.Equal(EventsVerificationErrorCode.InvalidToken, missingError.Error.Code);

        var wrongKid = RewriteAndResign(token, key, (header, _) => header["kid"] = "not-ap-1");
        var wrongError = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            resolver.ResolveSubscribeAsync(wrongKid, Audience));
        Assert.Equal(EventsVerificationErrorCode.UnknownKey, wrongError.Error.Code);
    }

    [Theory]
    [InlineData("missing-cnf")]
    [InlineData("missing-jwk")]
    [InlineData("rsa")]
    [InlineData("oct")]
    [InlineData("wrong-okp-curve")]
    [InlineData("missing-kty")]
    [Trait("Spec", "Events §Subscribe Token Structure/Verification L230-L269")]
    public void MalformedOrWrongTypeConfirmationKeysAreRejected(string caseName)
    {
        var key = AAuthKey.Generate();
        var token = RewriteAndResign(Build(key, AAuthKey.Generate()).Token, key,
            (_, payload) =>
            {
                switch (caseName)
                {
                    case "missing-cnf":
                        payload.Remove("cnf");
                        break;
                    case "missing-jwk":
                        payload["cnf"] = new JsonObject();
                        break;
                    case "rsa":
                        payload["cnf"]!["jwk"] = new JsonObject
                        {
                            ["kty"] = "RSA",
                            ["n"] = "AQ",
                            ["e"] = "AQAB",
                        };
                        break;
                    case "oct":
                        payload["cnf"]!["jwk"] = new JsonObject
                        {
                            ["kty"] = "oct",
                            ["k"] = "AQ",
                        };
                        break;
                    case "wrong-okp-curve":
                        payload["cnf"]!["jwk"] = new JsonObject
                        {
                            ["kty"] = "OKP",
                            ["crv"] = "P-256",
                            ["x"] = "AQ",
                        };
                        break;
                    case "missing-kty":
                        payload["cnf"]!["jwk"] = new JsonObject
                        {
                            ["crv"] = "Ed25519",
                            ["x"] = "AQ",
                        };
                        break;
                }
            });

        var verified = Verify(token, key);
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(verified));
    }

    [Theory]
    [InlineData("iss")]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("eid")]
    [InlineData("iat")]
    [InlineData("exp")]
    [InlineData("cnf")]
    [Trait("Spec", "Events §Subscribe Token Required payload claims L214-L239")]
    public void ReaderRejectsMissingRequiredClaims(string claim)
    {
        var key = AAuthKey.Generate();
        var verified = DecodeVerified(Build(key, AAuthKey.Generate()).Token, key);
        verified.Payload.Remove(claim);

        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(verified));
    }

    [Theory]
    [InlineData("iss")]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("eid")]
    [InlineData("iat")]
    [InlineData("exp")]
    [InlineData("max_uses")]
    [Trait("Spec", "Events §Subscribe Token Structure L214-L244; reader strictness")]
    public void ReaderRejectsWrongClaimTypesAndEmptyStrings(string claim)
    {
        var key = AAuthKey.Generate();
        var token = RewriteAndResign(Build(key, AAuthKey.Generate(), maxUses: 2).Token, key,
            (_, payload) =>
            {
                payload[claim] = claim is "iat" or "exp" or "max_uses"
                    ? "not-an-integer"
                    : " ";
            });

        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(Verify(token, key)));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269")]
    public void ResourceAudienceMustMatchTheResourceUrl()
    {
        var key = AAuthKey.Generate();
        var token = Build(key, AAuthKey.Generate(), audience: "https://other-resource.example").Token;

        Assert.Throws<TokenVerificationException>(() => Verify(token, key));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269; C20")]
    public void FutureIssuedTokenIsRejectedByCoreVerifier()
    {
        var key = AAuthKey.Generate();
        var token = Build(key, AAuthKey.Generate(),
            issuedAt: EventsTestData.Now.AddMinutes(2)).Token;

        Assert.Throws<TokenVerificationException>(() => Verify(token, key));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Verification L264-L269")]
    public void ExpiredTokenIsRejectedByCoreVerifier()
    {
        var key = AAuthKey.Generate();
        var token = Build(key, AAuthKey.Generate(),
            issuedAt: EventsTestData.Now.AddMinutes(-10),
            lifetime: TimeSpan.FromMinutes(5)).Token;

        Assert.Throws<TokenVerificationException>(() => Verify(token, key));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [Trait("Spec", "Events §Subscribe Token max_uses L244; issuance rules")]
    public void NonPositiveMaxUsesAreRejectedByIssuanceAndReader(long maxUses)
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            Build(key, AAuthKey.Generate(), maxUses: maxUses));

        var valid = Build(key, AAuthKey.Generate()).Token;
        var rewritten = RewriteAndResign(valid, key, (_, payload) => payload["max_uses"] = maxUses);
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(Verify(rewritten, key)));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token eid L232-L236; C16")]
    public void EmptyEventIdIsRejectedByIssuanceAndReader()
    {
        var key = AAuthKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            Build(key, AAuthKey.Generate(), eid: " "));

        var valid = Build(key, AAuthKey.Generate()).Token;
        var rewritten = RewriteAndResign(valid, key, (_, payload) => payload["eid"] = " ");
        Assert.Throws<TokenVerificationException>(() => SubscribeTokenClaims.Read(Verify(rewritten, key)));
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token iss/aud URL rules L214-L221; C16")]
    public void IssuanceAllowsHttpsAndLoopbackHttpButRejectsOtherHttp()
    {
        var key = AAuthKey.Generate();
        var confirmation = AAuthKey.Generate();
        Assert.NotEmpty(Build(key, confirmation, issuer: "https://ap.example").Token);
        Assert.NotEmpty(Build(key, confirmation, issuer: "http://localhost:5301").Token);
        Assert.NotEmpty(Build(key, confirmation, issuer: "http://127.0.0.1:5301").Token);
        Assert.NotEmpty(Build(key, confirmation, issuer: "http://[::1]:5301").Token);
        Assert.NotEmpty(Build(key, confirmation, audience: "http://localhost:5301").Token);
        Assert.Throws<InvalidOperationException>(() =>
            Build(key, confirmation, issuer: "http://ap.example"));
        Assert.Throws<InvalidOperationException>(() =>
            Build(key, confirmation, audience: "http://resource.example"));
    }

    [Theory]
    [InlineData("https://example.com", true)]
    [InlineData("http://localhost:5301", true)]
    [InlineData("http://127.0.0.1:5301", true)]
    [InlineData("http://[::1]:5301", true)]
    [InlineData("http://example.com", false)]
    [InlineData("https://127.0.0.1", true)]
    [InlineData("https://192.168.1.10", false)]
    [Trait("Spec", "Events §Subscribe Token iss/aud URL rules L214-L221")]
    public async Task UrlPolicyEnforcesHttpsLoopbackAndPrivateAddressRules(string value, bool expected)
    {
        var allowed = await new DefaultEventsUrlPolicy().IsAllowedAsync(new Uri(value));

        Assert.Equal(expected, allowed);
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token eid L232-L236; C16")]
    public void GeneratedEventIdsHave128BitsBase64UrlEncodingAndFreshEntropy()
    {
        var key = AAuthKey.Generate();
        var ids = Enumerable.Range(0, 64)
            .Select(_ => EventsTestData.Subscribe(key).Eid)
            .ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
        foreach (var eid in ids)
        {
            Assert.DoesNotContain('+', eid);
            Assert.DoesNotContain('/', eid);
            Assert.DoesNotContain('=', eid);
            Assert.Equal(16, Base64UrlEncoder.DecodeBytes(eid).Length);
        }
    }

    [Fact]
    [Trait("Spec", "Events §Subscribe Token Structure L209-L244; reader strictness")]
    public void ReaderRequiresNonEmptyAgentAndAbsoluteHttpsClaims()
    {
        var key = AAuthKey.Generate();
        foreach (var mutate in new Action<JsonObject>[]
        {
            payload => payload["sub"] = "not-an-agent",
            payload => payload["iss"] = "http://not-loopback.example",
            payload => payload["aud"] = "not-a-url",
            payload => payload["eid"] = "",
            payload => payload["exp"] = payload["iat"]!.GetValue<long>(),
        })
        {
            var token = Build(key, AAuthKey.Generate()).Token;
            var rewritten = RewriteAndResign(token, key, (_, payload) => mutate(payload));
            Assert.Throws<TokenVerificationException>(() =>
                SubscribeTokenClaims.Read(Verify(rewritten, key)));
        }
    }

    [Fact]
    [Trait("Spec", "Events §Event Token L348-L359; C23")]
    public void EventIssuanceAddsFreshRandomJtiForTokenIdentity()
    {
        var key = AAuthKey.Generate();
        var first = EventsTestData.Event(key).Token;
        var second = EventsTestData.Event(key).Token;
        var firstJti = Decode(first).Payload["jti"]!.GetValue<string>();
        var secondJti = Decode(second).Payload["jti"]!.GetValue<string>();

        Assert.NotEqual(firstJti, secondJti);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(firstJti).Length);
        Assert.Equal(16, Base64UrlEncoder.DecodeBytes(secondJti).Length);
    }

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();

    private static SubscribeTokenArtifact Build(
        IAAuthKey key,
        IAAuthKey confirmationKey,
        string issuer = Issuer,
        string subject = Subject,
        string audience = Audience,
        string? eid = "eid-1",
        long? maxUses = null,
        DateTimeOffset? issuedAt = null,
        TimeSpan? lifetime = null) =>
        new SubscribeTokenBuilder
        {
            Issuer = issuer,
            Subject = subject,
            Audience = audience,
            KeyId = Kid,
            Key = key,
            ConfirmationKey = confirmationKey,
            EventId = eid,
            MaxUses = maxUses,
            IssuedAt = issuedAt ?? EventsTestData.Now,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
        }.Build();

    private static TokenVerifier.VerifiedToken Verify(string token, IAAuthKey key) =>
        new TokenVerifier
        {
            Clock = () => EventsTestData.Now,
            ClockSkew = TimeSpan.Zero,
        }.Verify(token, key, AAuthEventsConstants.SubscribeTokenType,
            AAuthEventsConstants.AgentDwk, Audience);

    private static TokenVerifier.VerifiedToken DecodeVerified(string token, IAAuthKey key) =>
        new TokenVerifier
        {
            Clock = () => EventsTestData.Now,
            ClockSkew = TimeSpan.Zero,
        }.Verify(token, key, AAuthEventsConstants.SubscribeTokenType,
            AAuthEventsConstants.AgentDwk);

    private static (JsonObject Header, JsonObject Payload) Decode(string token) =>
        (
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]))!.AsObject(),
            JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject()
        );

    private static string RewriteAndResign(
        string compact,
        IAAuthKey key,
        Action<JsonObject, JsonObject> mutate)
    {
        var parts = compact.Split('.');
        var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1]))!.AsObject();
        mutate(header, payload);
        var headerSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadSegment = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var input = headerSegment + "." + payloadSegment;
        return input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }

    private static EventsJwtKeyResolver CreateResolver(IAAuthKey key, string kid)
    {
        var http = new HttpClient(new JwksHandler(key, kid));
        return new EventsJwtKeyResolver(
            http,
            new DefaultEventsUrlPolicy(),
            new TokenVerifier
            {
                Clock = () => EventsTestData.Now,
                ClockSkew = TimeSpan.Zero,
            });
    }

    private sealed class JwksHandler(IAAuthKey key, string kid) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.RequestUri?.ToString() == $"{Issuer}/.well-known/{AAuthEventsConstants.AgentDwk}")
                return Task.FromResult(Json(new JsonObject
                {
                    ["issuer"] = Issuer,
                    ["jwks_uri"] = $"{Issuer}/jwks",
                }));
            if (request.RequestUri?.ToString() == $"{Issuer}/jwks")
            {
                var jwk = key.ToPublicJwk();
                jwk["kid"] = kid;
                jwk["alg"] = key.Algorithm;
                return Task.FromResult(Json(new JsonObject
                {
                    ["keys"] = new JsonArray(jwk),
                }));
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage Json(JsonObject value) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    value.ToJsonString(), Encoding.UTF8, AAuthEventsConstants.JsonMediaType),
            };
    }
}
