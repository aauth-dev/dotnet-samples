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
    [Fact]
    public void VerifySelfIssuedAgentToken_AcceptsHappyPath()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
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
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
            IssuedAt = issued,
            Lifetime = TimeSpan.FromMinutes(1),
        }.Build();

        var verifier = new TokenVerifier { Clock = () => issued.AddHours(1) };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifySelfIssuedAgentToken(jwt, key));
    }

    [Fact]
    public void Verify_RejectsWrongTyp()
    {
        var key = AAuthKey.Generate();
        var jwt = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
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
            Issuer = "https://resource.example",
            Audience = "https://ps.example",
            Agent = "aauth:a@ap.example",
            AgentJkt = key.ComputeJwkThumbprint(),
            Key = rkey,
            KeyId = "r",
        }.Build();

        var verifier = new TokenVerifier();
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
            Issuer = "https://ap.example",
            Subject = "aauth:x@ap.example",
            KeyId = "k",
            Key = key,
        }.Build();

        var verifier = new TokenVerifier();
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
            new MetadataClient(new HttpClient(new ResourceJwksHandler(resKey, ResKid, ResIss))),
            new JwksClient(new HttpClient(new ResourceJwksHandler(resKey, ResKid, ResIss))));
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

        var verifier = new TokenVerifier();
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

        var verifier = new TokenVerifier();
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

        var verifier = new TokenVerifier { Clock = () => issued.AddHours(1) };
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

        var verifier = new TokenVerifier();
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

        var verifier = new TokenVerifier();
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

        var verifier = new TokenVerifier();
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
            Issuer = ResIss,
            Subject = AgentId,
            KeyId = ResKid,
            Key = resKey,
        }.Build();
        var (meta, jwks) = Discovery(resKey);

        var verifier = new TokenVerifier();
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
            jwk["alg"] = AAuthKey.Algorithm;
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
