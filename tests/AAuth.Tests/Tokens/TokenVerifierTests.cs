using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class TokenVerifierTests
{
    [Theory]
    [MemberData(nameof(TestTokens.InvalidRequiredClaims), MemberType = typeof(TestTokens))]
    public async Task RawBuiltInMandatoryClaimsRejectBeforeDiscovery(string type, string claim, string mutation)
    {
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, type, (header, payload) => TestTokens.Mutate(header, payload, claim, mutation));
        var verifier = new TokenVerifier { Clock = () => DateTimeOffset.FromUnixTimeSeconds(1800000000) };
        var dwk = type == AgentTokenBuilder.TokenType ? AgentTokenBuilder.AgentDwk
            : type == ResourceTokenBuilder.TokenType ? ResourceTokenBuilder.ResourceDwk : AuthTokenBuilder.PersonDwk;
        Assert.Equal(AAuth.Errors.SignatureErrorCode.InvalidJwt,
            Assert.Throws<TokenVerificationException>(() => verifier.Verify(jwt, key, type, dwk)).Code);
        using var http = new InProcessHttpClient(new NoDiscovery());
        using var metadata = new MetadataClient(http);
        using var jwks = new JwksClient(http);
        Assert.Equal(AAuth.Errors.SignatureErrorCode.InvalidJwt, (await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyWithJwksAsync(jwt, metadata, jwks, type, dwk, null))).Code);
        if (type == AuthTokenBuilder.TokenType)
            Assert.Equal(AAuth.Errors.SignatureErrorCode.InvalidJwt, (await Assert.ThrowsAsync<TokenVerificationException>(() =>
                verifier.VerifyAuthTokenWithJwksAsync(jwt, metadata, jwks, "https://resource.example", key, "aauth:wire@issuer.example"))).Code);
    }

    private sealed class NoDiscovery : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new Xunit.Sdk.XunitException("Malformed token must fail before discovery.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResourceAuthorizationHasExplicitScopeOrR3Pair(bool r3)
    {
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, ResourceTokenBuilder.TokenType, (_, payload) =>
        {
            if (r3)
            {
                payload.Remove("scope");
                payload["r3_uri"] = "https://resource.example/r3/document";
                payload["r3_s256"] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(new byte[32]);
            }
            else payload["scope"] = "";
        });
        Assert.NotNull(new TokenVerifier { Clock = () => DateTimeOffset.FromUnixTimeSeconds(1800000000) }
            .Verify(jwt, key, ResourceTokenBuilder.TokenType, ResourceTokenBuilder.ResourceDwk));
    }

    [Theory]
    [InlineData("kid", true)]
    [InlineData("iss", false)]
    [InlineData("dwk", false)]
    [InlineData("sub", false)]
    [InlineData("jti", false)]
    [InlineData("iat", false)]
    public void Verify_RequiresAgentClaims(string claim, bool inHeader)
    {
        IAAuthKey key = AAuthKey.Generate();
        foreach (var mutation in new[] { "absent", "null", "wrong-type", "blank" })
        {
            var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = AgentTokenBuilder.TokenType, ["kid"] = "issuer" };
            var payload = new JsonObject
            {
                ["iss"] = "https://ap.example", ["dwk"] = AgentTokenBuilder.AgentDwk,
                ["sub"] = "aauth:test@ap.example", ["jti"] = "token-id",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
                ["cnf"] = new JsonObject { ["jwk"] = key.ToPublicJwk() },
            };
            var target = inHeader ? header : payload;
            if (mutation == "absent") target.Remove(claim);
            else target[claim] = mutation switch { "null" => null, "wrong-type" => new JsonArray(123), _ => JsonValue.Create("") };
            var jwt = SignRaw(header, payload, key);
            Assert.Throws<TokenVerificationException>(() => new TokenVerifier().VerifySelfIssuedAgentToken(jwt, key));
        }
    }

    [Fact]
    public void VerifyAuthToken_RejectsNumericAudienceWithTypedError()
    {
        IAAuthKey key = AAuthKey.Generate();
        var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = AuthTokenBuilder.TokenType, ["kid"] = "issuer" };
        var payload = new JsonObject
        {
            ["iss"] = "https://ps.example", ["dwk"] = AuthTokenBuilder.PersonDwk, ["aud"] = 123,
            ["agent"] = "aauth:test@ap.example", ["sub"] = "person", ["jti"] = "token-id",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["cnf"] = new JsonObject { ["jwk"] = key.ToPublicJwk() },
        };
        Assert.Throws<TokenVerificationException>(() => new TokenVerifier().VerifyAuthToken(
            SignRaw(header, payload, key), key, "https://resource.example", key, "aauth:test@ap.example"));
    }

    private static string SignRaw(JsonObject header, JsonObject payload, IAAuthKey key)
    {
        var input = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(header.ToJsonString()) + "."
            + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }

    [Fact]
    public void VerifySelfIssuedAgentToken_AcceptsHappyPath()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var verified = verifier.VerifySelfIssuedAgentToken(jwt, key);

        Assert.Equal("aa-agent+jwt", verified.TokenType);
        Assert.Equal("https://ap.example", verified.Issuer);
    }

    [Fact]
    public void Verify_RejectsExpiredToken()
    {
        var key = AAuthKey.Generate();
        var issued = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var jwt = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
            IssuedAt = issued,
            Lifetime = TimeSpan.FromMinutes(1),
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy, Clock = () => issued.AddHours(1) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, key));
    }

    [Fact]
    public void Verify_RejectsWrongTyp()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.Verify(jwt, key, "aa-resource+jwt", "aauth-resource.json"));
    }

    [Fact]
    public void Verify_RejectsWrongAudience()
    {
        var key = AAuthKey.Generate();
        var rkey = AAuthKey.Generate();
        var jwt = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            Agent = "aauth:a@ap.example",
            AgentJkt = key.ComputeJwkThumbprint(),
            Key = rkey,
            KeyId = "r",
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.Verify(jwt, rkey, "aa-resource+jwt", "aauth-resource.json", "https://other.example"));
    }

    [Fact]
    public void Verify_RejectsBadSignature()
    {
        var key = AAuthKey.Generate();
        var other = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, other));
    }

    // ----------------------------------------------------------------
    // VerifyResourceTokenAsync (§"Resource Token Verification", Phase 10)
    // ----------------------------------------------------------------

    private const string ResIss = "https://resource.example";
    private const string ResKid = "res-1";
    private const string PsAud = "https://ps.example";
    private const string AgentId = "aauth:a@ap.example";

    private static (MetadataClient Meta, JwksClient Jwks) Discovery(AAuthKey resKey)
    {
        // Two handlers because MetadataClient and JwksClient each own one.
        return (
            new MetadataClient(new InProcessHttpClient(new ResourceJwksHandler(resKey, ResKid, ResIss))),
            new JwksClient(new InProcessHttpClient(new ResourceJwksHandler(resKey, ResKid, ResIss))));
    }

    private static string BuildResourceToken(
        AAuthKey signingKey,
        AAuthKey agentKey,
        string agent = AgentId,
        string audience = PsAud,
        DateTimeOffset? issuedAt = null,
        TimeSpan? lifetime = null)
        => new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = ResIss,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = signingKey,
            KeyId = ResKid,
            Scope = "whoami",
            IssuedAt = issuedAt,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
        }.Build();

    [Fact]
    public async Task VerifyResourceTokenAsync_AcceptsHappyPath()
    {
        var resKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = BuildResourceToken(resKey, agentKey);
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var verified = await verifier.VerifyResourceTokenAsync(
            jwt, PsAud, AgentId, agentKey.ComputeJwkThumbprint(), meta, jwks);

        Assert.Equal(ResourceTokenBuilder.TokenType, verified.TokenType);
        Assert.Equal(ResIss, verified.Issuer);
        Assert.Equal(AgentId, (string?)verified.Payload["agent"]);
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsBadSignature()
    {
        // Token signed by a key the resource's published JWKS does not hold.
        var publishedKey = AAuthKey.Generate();
        var forgedKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = BuildResourceToken(forgedKey, agentKey);
        var (meta, jwks) = Discovery(publishedKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                jwt, PsAud, AgentId, agentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsExpired()
    {
        var resKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var issued = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var jwt = BuildResourceToken(resKey, agentKey, issuedAt: issued, lifetime: TimeSpan.FromMinutes(1));
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy, Clock = () => issued.AddHours(1) };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                jwt, PsAud, AgentId, agentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsWrongAudience()
    {
        var resKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = BuildResourceToken(resKey, agentKey, audience: PsAud);
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                jwt, "https://other-ps.example", AgentId, agentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsWrongAgent()
    {
        var resKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = BuildResourceToken(resKey, agentKey, agent: AgentId);
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                jwt, PsAud, "aauth:someone-else@ap.example", agentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsWrongAgentJkt()
    {
        // Resource token bound to one agent key; a different key presented.
        var resKey = AAuthKey.Generate();
        var boundAgentKey = AAuthKey.Generate();
        var otherAgentKey = AAuthKey.Generate();
        var jwt = BuildResourceToken(resKey, boundAgentKey);
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                jwt, PsAud, AgentId, otherAgentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    [Fact]
    public async Task VerifyResourceTokenAsync_RejectsWrongTokenType()
    {
        // An agent token carries typ=aa-agent+jwt and dwk=aauth-agent.json,
        // so the resource-token (typ/dwk) checks must reject it.
        var resKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var notAResourceToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ResIss,
            Subject = AgentId,
            KeyId = ResKid,
            Key = resKey,
        }.Build();
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        await Assert.ThrowsAsync<TokenVerificationException>(() =>
            verifier.VerifyResourceTokenAsync(
                notAResourceToken, PsAud, AgentId, agentKey.ComputeJwkThumbprint(), meta, jwks));
    }

    /// <summary>
    /// In-process stub serving the resource's well-known metadata + JWKS so
    /// <see cref="TokenVerifier.VerifyResourceTokenAsync"/> can resolve the
    /// signing key during unit tests.
    /// </summary>
    private sealed class ResourceJwksHandler : HttpMessageHandler
    {
        private readonly string _metadataJson;
        private readonly string _jwksJson;

        public ResourceJwksHandler(AAuthKey key, string kid, string issuer)
        {
            _metadataJson = new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
            }.ToJsonString();

            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Ed25519Algorithm;
            _jwksJson = new JsonObject
            {
                ["keys"] = new JsonArray(jwk),
            }.ToJsonString();
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            string json;
            if (path == "/.well-known/aauth-resource.json")
                json = _metadataJson;
            else if (path == "/.well-known/jwks.json")
                json = _jwksJson;
            else
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }
    }
}
