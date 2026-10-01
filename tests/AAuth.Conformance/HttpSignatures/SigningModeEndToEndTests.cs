using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// End-to-end conformance tests for all four AAuth signing modes per
/// §HTTP Signature Profile and §Keying Material.
/// </summary>
public class SigningModeEndToEndTests
{
    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private static readonly DateTimeOffset FixedClock = new(2026, 5, 22, 12, 0, 0, TimeSpan.Zero);

    private static async Task<HttpRequestMessage> SignRequest(
        IAAuthSigner key, ISignatureKeyProvider provider, string url = "https://r.example/resource")
    {
        var capture = new CaptureHandler();
        var handler = new AAuthSigningHandler(key, provider, new FakeTimeProvider(FixedClock))
        {
            InnerHandler = capture
        };
        using var client = new InProcessHttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
        return capture.Captured!;
    }

    private static AAuthVerifier CreateVerifier() => new()
    {
        TimeProvider = new FakeTimeProvider(FixedClock),
    };

    // ────────────────────────────────────────────────────────────────────────
    // §Keying Material — "For `identity`: the agent uses `scheme=jwt`"
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Signing Modes — jwt scheme: sign and verify round-trip")]
    public async Task JwtScheme_SignAndVerify()
    {
        var signingKey = AAuthKey.Generate();
        var apKey = AAuthKey.Generate();
        var token = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Key = apKey,
            KeyId = "ap-key-1",
            PersonServer = "https://ps.example",
            ConfirmationKey = signingKey,
        }.BuildAsync();

        var provider = new JwtSignatureKeyProvider(() => token);
        var request = await SignRequest(signingKey, provider);

        // Extract headers
        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        // Parse and verify
        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jwt", info.Scheme);
        Assert.Null(info.ConfirmationKey);
        new TokenVerifier { EgressPolicy = TestEgress.Policy }.Verify(token, apKey, AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk);

        var verifier = CreateVerifier();
        verifier.Verify(
            method: "GET",
            authority: "r.example",
            path: "/resource",
            signatureKey: sigKeyHeader,
            signatureInput: sigInput,
            signatureHeader: sig,
            publicKey: signingKey);
    }

    // ────────────────────────────────────────────────────────────────────────
    // §Keying Material — "For `pseudonym`: the agent uses `scheme=hwk`"
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Signing Modes — hwk scheme: sign and verify round-trip (inline key)")]
    public async Task HwkScheme_SignAndVerify()
    {
        var key = AAuthKey.Generate();
        var provider = new HwkSignatureKeyProvider(key);
        var request = await SignRequest(key, provider);

        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        // Parse — hwk carries the inline public key per spec
        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("hwk", info.Scheme);
        Assert.Equal(key.ComputeJwkThumbprint(), info.Jkt);
        Assert.NotNull(info.ConfirmationKey); // Inline per spec

        // Verify using the inline key (no external lookup needed)
        var verifier = CreateVerifier();
        verifier.Verify(
            method: "GET",
            authority: "r.example",
            path: "/resource",
            signatureKey: sigKeyHeader,
            signatureInput: sigInput,
            signatureHeader: sig,
            publicKey: info.ConfirmationKey);
    }

    // ────────────────────────────────────────────────────────────────────────
    // §Keying Material — "For `identity`: the agent uses `scheme=jwks_uri`"
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Signing Modes — jwks_uri scheme: sign and verify round-trip")]
    public async Task JwksUriScheme_SignAndVerify()
    {
        var key = AAuthKey.Generate();
        var provider = new JwksUriSignatureKeyProvider(
            "https://agent.example", "aauth-agent.json", "agent-key-1");
        var request = await SignRequest(key, provider);

        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jwks_uri", info.Scheme);
        Assert.Equal("https://agent.example", info.Identifier);
        Assert.Equal("agent-key-1", info.Kid);

        // Verify with the key (simulating resolution from JWKS endpoint)
        var verifier = CreateVerifier();
        var pubKey = AAuthKey.FromJwk(key.ToPublicJwk());
        verifier.Verify(
            method: "GET",
            authority: "r.example",
            path: "/resource",
            signatureKey: sigKeyHeader,
            signatureInput: sigInput,
            signatureHeader: sig,
            publicKey: pubKey);
    }

    // ────────────────────────────────────────────────────────────────────────
    // §Bootstrap — "scheme=jkt-jwt: naming JWT + ephemeral key"
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Signing Modes — jkt-jwt scheme: sign and verify round-trip")]
    public async Task JktJwtScheme_SignAndVerify()
    {
        // Durable key (signs the naming JWT)
        var durableKey = AAuthKey.Generate();
        // Ephemeral key (signs the HTTP request)
        var ephemeralKey = AAuthKey.Generate();

        // Build a self-issued naming JWT (draft-04 §3.4): durable key signs, its
        // public key is in the header, iss is its thumbprint URN, cnf.jwk is the
        // ephemeral public key.
        var namingJwt = await AAuth.Agent.NamingJwtBuilder.BuildAsync(durableKey, ephemeralKey);

        var provider = new JktJwtSignatureKeyProvider(() => namingJwt);
        var request = await SignRequest(ephemeralKey, provider);

        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jkt-jwt", info.Scheme);
        // The reported pseudonym is the durable key's thumbprint (§7.1).
        var naming = NamingTokenVerifier.Verify(info.Jwt!, DateTimeOffset.UtcNow, TimeSpan.Zero);
        Assert.Equal(durableKey.ComputeJwkThumbprint(), naming.DurableKey.ComputeJwkThumbprint());

        // The naming JWT's cnf.jwk should be the ephemeral key
        Assert.Equal(
            ephemeralKey.ComputeJwkThumbprint(),
            naming.ConfirmationKey.ComputeJwkThumbprint());

        // The single-parameter wire format carries only the jwt.
        Assert.StartsWith("sig=jkt-jwt;jwt=\"", sigKeyHeader);
        Assert.DoesNotContain(";jkt=", sigKeyHeader);

        // Verify the HTTP signature using the ephemeral key
        var verifier = CreateVerifier();
        verifier.Verify(
            method: "GET",
            authority: "r.example",
            path: "/resource",
            signatureKey: sigKeyHeader,
            signatureInput: sigInput,
            signatureHeader: sig,
            publicKey: naming.ConfirmationKey);
    }

    // ────────────────────────────────────────────────────────────────────────
    // §Verification step 5 — resolver dispatch tests
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver resolves jwt scheme")]
    public async Task Resolver_Jwt()
    {
        var signingKey = AAuthKey.Generate();
        var apKey = AAuthKey.Generate();
        var token = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Key = apKey,
            KeyId = "ap-key-1",
            PersonServer = "https://ps.example",
            ConfirmationKey = signingKey,
        }.BuildAsync();
        var header = SignatureKeyHeader.FormatJwt(token);
        var info = SignatureKeyParser.ParseAny(header);

        var http = new InProcessHttpClient(new IssuerDiscoveryFixture("https://ap.example", apKey, "ap-key-1"));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http));
        var result = await resolver.ResolveAsync(info);

        Assert.Equal(signingKey.ComputeJwkThumbprint(), result.PublicKey.ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver resolves hwk from inline key")]
    public async Task Resolver_Hwk()
    {
        var key = AAuthKey.Generate();
        var provider = new HwkSignatureKeyProvider(key);
        var header = provider.GetSignatureKeyHeader();
        var info = SignatureKeyParser.ParseAny(header);

        var resolver = new DefaultSignatureKeyResolver();
        var result = await resolver.ResolveAsync(info);

        Assert.Equal(key.ComputeJwkThumbprint(), result.PublicKey.ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver resolves self-anchored jkt-jwt")]
    public async Task Resolver_JktJwt()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();
        var namingJwt = await AAuth.Agent.NamingJwtBuilder.BuildAsync(durableKey, ephemeralKey);

        var header = SignatureKeyHeader.FormatJktJwt(namingJwt);
        var info = SignatureKeyParser.ParseAny(header);

        var resolver = new DefaultSignatureKeyResolver();
        var result = await resolver.ResolveAsync(info);

        // Resolution returns the ephemeral key (cnf.jwk) that signs HTTP requests.
        Assert.Equal(ephemeralKey.ComputeJwkThumbprint(), result.PublicKey.ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver rejects jkt-jwt with spoofed iss")]
    public async Task Resolver_JktJwt_ThumbprintMismatch()
    {
        var attackerKey = AAuthKey.Generate();
        var victimKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();

        // Header jwk = attacker's key, but iss claims the victim's thumbprint —
        // self-anchored verification (§3.4 step 7) must reject this.
        var jwtHeader = new System.Text.Json.Nodes.JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = attackerKey.ToPublicJwk(),
        };
        var now = DateTimeOffset.UtcNow;
        var jwtPayload = new System.Text.Json.Nodes.JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + victimKey.ComputeJwkThumbprint(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new System.Text.Json.Nodes.JsonObject { ["jwk"] = ephemeralKey.ToPublicJwk() },
        };
        var namingJwt = await JwtWriter.SignCompactAsync(jwtHeader, jwtPayload, attackerKey);
        var header = SignatureKeyHeader.FormatJktJwt(namingJwt);
        var info = SignatureKeyParser.ParseAny(header);

        var resolver = new DefaultSignatureKeyResolver();
        var ex = await Assert.ThrowsAsync<AAuthVerificationException>(
            () => resolver.ResolveAsync(info));
        Assert.Contains("does not match", ex.Message);
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver rejects jwks_uri with non-https scheme")]
    public async Task Resolver_JwksUri_RejectsNonHttps()
    {
        var info = new SignatureKeyParser.ParsedSignatureKeyInfo
        {
            Scheme = "jwks_uri",
            Identifier = "http://evil.example",
            Dwk = "config",
            Kid = "k1",
        };

        var http = new InProcessHttpClient(new IssuerDiscoveryFixture("https://allowed.example", AAuthKey.Generate(), "key"));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http));
        var ex = await Assert.ThrowsAsync<AAuthVerificationException>(
            () => resolver.ResolveAsync(info));
        Assert.Equal(AAuth.Errors.SignatureErrorCode.InvalidKey, ex.Code);
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver allows loopback jwks_uri for dev")]
    public async Task Resolver_JwksUri_AllowsLoopback()
    {
        var info = new SignatureKeyParser.ParsedSignatureKeyInfo
        {
            Scheme = "jwks_uri",
            Identifier = "http://localhost:59999",
            Dwk = "config",
            Kid = "k1",
        };

        using var http = AAuthHttpTransport.CreateClient(AAuthEgressPolicy.ForDevelopmentLoopback("http://localhost:59999"));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http));
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => resolver.ResolveAsync(info));
    }
}
