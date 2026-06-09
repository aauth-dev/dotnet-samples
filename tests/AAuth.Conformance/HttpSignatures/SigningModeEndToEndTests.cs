using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
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
        IAAuthKey key, ISignatureKeyProvider provider, string url = "https://r.example/resource")
    {
        var capture = new CaptureHandler();
        var handler = new AAuthSigningHandler(key, provider, () => FixedClock)
        {
            InnerHandler = capture
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
        return capture.Captured!;
    }

    private static AAuthVerifier CreateVerifier() => new()
    {
        Clock = () => FixedClock,
    };

    // ────────────────────────────────────────────────────────────────────────
    // §Keying Material — "For `identity`: the agent uses `scheme=jwt`"
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Signing Modes — jwt scheme: sign and verify round-trip")]
    public async Task JwtScheme_SignAndVerify()
    {
        var signingKey = AAuthKey.Generate();
        var apKey = AAuthKey.Generate();
        var token = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Key = apKey,
            KeyId = "ap-key-1",
            PersonServer = "https://ps.example",
            ConfirmationKey = signingKey,
        }.Build();

        var provider = new JwtSignatureKeyProvider(() => token);
        var request = await SignRequest(signingKey, provider);

        // Extract headers
        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        // Parse and verify
        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jwt", info.Scheme);
        Assert.NotNull(info.ConfirmationKey);

        var verifier = CreateVerifier();
        verifier.Verify(
            method: "GET",
            authority: "r.example",
            path: "/resource",
            signatureKey: sigKeyHeader,
            signatureInput: sigInput,
            signatureHeader: sig,
            publicKey: info.ConfirmationKey!);
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
            "https://agent.example/.well-known/jwks.json", "agent-key-1");
        var request = await SignRequest(key, provider);

        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jwks_uri", info.Scheme);
        Assert.Equal("https://agent.example/.well-known/jwks.json", info.JwksUri);
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
        var namingJwt = AAuth.Agent.NamingJwtBuilder.Build(durableKey, ephemeralKey);

        var provider = new JktJwtSignatureKeyProvider(() => namingJwt);
        var request = await SignRequest(ephemeralKey, provider);

        var sigKeyHeader = request.Headers.GetValues("Signature-Key").Single();
        var sigInput = request.Headers.GetValues("Signature-Input").Single();
        var sig = request.Headers.GetValues("Signature").Single();

        var info = SignatureKeyParser.ParseAny(sigKeyHeader);
        Assert.Equal("jkt-jwt", info.Scheme);
        // The reported pseudonym is the durable key's thumbprint (§7.1).
        Assert.Equal(durableKey.ComputeJwkThumbprint(), info.Jkt);
        Assert.NotNull(info.ConfirmationKey);

        // The naming JWT's cnf.jwk should be the ephemeral key
        Assert.Equal(
            ephemeralKey.ComputeJwkThumbprint(),
            info.ConfirmationKey!.ComputeJwkThumbprint());

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
            publicKey: info.ConfirmationKey!);
    }

    // ────────────────────────────────────────────────────────────────────────
    // §Verification step 5 — resolver dispatch tests
    // ────────────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver resolves jwt scheme")]
    public async Task Resolver_Jwt()
    {
        var signingKey = AAuthKey.Generate();
        var apKey = AAuthKey.Generate();
        var token = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:agent@ap.example",
            Key = apKey,
            KeyId = "ap-key-1",
            PersonServer = "https://ps.example",
            ConfirmationKey = signingKey,
        }.Build();
        var header = SignatureKeyHeader.FormatJwt(token);
        var info = SignatureKeyParser.ParseAny(header);

        var resolver = new DefaultSignatureKeyResolver();
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
        var namingJwt = AAuth.Agent.NamingJwtBuilder.Build(durableKey, ephemeralKey);

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
            ["alg"] = AAuthKey.Algorithm,
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
        var namingJwt = JwtWriter.SignCompact(jwtHeader, jwtPayload, attackerKey);
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
            JwksUri = "http://evil.example/jwks",
            Kid = "k1",
        };

        var resolver = new DefaultSignatureKeyResolver(jwksClient: new JwksClient(new HttpClient()));
        var ex = await Assert.ThrowsAsync<AAuthVerificationException>(
            () => resolver.ResolveAsync(info));
        Assert.Contains("must use https", ex.Message);
    }

    [Fact(DisplayName = "§Verification — DefaultSignatureKeyResolver allows loopback jwks_uri for dev")]
    public async Task Resolver_JwksUri_AllowsLoopback()
    {
        // This test verifies that loopback URIs are permitted (dev mode),
        // even though the actual JWKS fetch will fail (no server running).
        var info = new SignatureKeyParser.ParsedSignatureKeyInfo
        {
            Scheme = "jwks_uri",
            JwksUri = "http://localhost:59999/.well-known/jwks.json",
            Kid = "k1",
        };

        // We expect it to get past the scheme check and fail on the HTTP fetch
        var resolver = new DefaultSignatureKeyResolver(jwksClient: new JwksClient(new HttpClient()));
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => resolver.ResolveAsync(info));
        // The fact that it threw HttpRequestException (not AAuthVerificationException
        // about https) confirms the loopback allowance works.
    }
}
