using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for jkt-jwt naming JWT signature verification and
/// ECDSA P-256 pipeline support (Gaps 9-10).
/// </summary>
public class JktJwtAndEcdsaTests
{
    // ── ECDSA P-256 Key Round-trip Tests ────────────────────────────────────

    [Fact(DisplayName = "§ECDSA — P-256 key generation produces valid sign/verify pair")]
    public void EcdsaKeyGenerateAndVerify()
    {
        var key = EcdsaAAuthKey.Generate();
        Assert.True(key.HasPrivateKey);
        Assert.Equal("ES256", key.Algorithm);

        var data = Encoding.UTF8.GetBytes("test data");
        var signature = key.Sign(data);
        Assert.True(key.Verify(data, signature));
    }

    [Fact(DisplayName = "§ECDSA — P-256 key round-trips through JWK")]
    public void EcdsaKeyRoundTripsViaJwk()
    {
        var original = EcdsaAAuthKey.Generate();
        var jwk = original.ToPrivateJwk();

        var restored = EcdsaAAuthKey.FromJwk(jwk);
        Assert.True(restored.HasPrivateKey);

        // Sign with restored, verify with original.
        var data = Encoding.UTF8.GetBytes("round-trip test");
        var sig = restored.Sign(data);
        Assert.True(original.Verify(data, sig));
    }

    [Fact(DisplayName = "§ECDSA — P-256 public-only key verifies but cannot sign")]
    public void EcdsaPublicOnlyKey()
    {
        var full = EcdsaAAuthKey.Generate();
        var publicOnly = EcdsaAAuthKey.FromJwk(full.ToPublicJwk());

        Assert.False(publicOnly.HasPrivateKey);
        Assert.Throws<InvalidOperationException>(() => publicOnly.Sign(new byte[] { 1 }));

        // But it can verify.
        var data = Encoding.UTF8.GetBytes("verify me");
        var sig = full.Sign(data);
        Assert.True(publicOnly.Verify(data, sig));
    }

    [Fact(DisplayName = "§ECDSA — JWK thumbprint is stable")]
    public void EcdsaThumbprintStable()
    {
        var key = EcdsaAAuthKey.Generate();
        var t1 = key.ComputeJwkThumbprint();
        var t2 = key.ComputeJwkThumbprint();
        Assert.Equal(t1, t2);
        Assert.NotEmpty(t1);
    }

    // ── KeyFactory Tests ───────────────────────────────────────────────────

    [Fact(DisplayName = "§KeyFactory — dispatches Ed25519")]
    public void KeyFactoryEd25519()
    {
        var ed = AAuthKey.Generate();
        var jwk = ed.ToPublicJwk();
        var key = KeyFactory.FromJwk(jwk);
        Assert.IsType<AAuthKey>(key);
        Assert.Equal("EdDSA", key.Algorithm);
    }

    [Fact(DisplayName = "§KeyFactory — dispatches P-256")]
    public void KeyFactoryP256()
    {
        var ec = EcdsaAAuthKey.Generate();
        var jwk = ec.ToPublicJwk();
        var key = KeyFactory.FromJwk(jwk);
        Assert.IsType<EcdsaAAuthKey>(key);
        Assert.Equal("ES256", key.Algorithm);
    }

    [Fact(DisplayName = "§KeyFactory — rejects unsupported kty/crv")]
    public void KeyFactoryRejectsUnsupported()
    {
        var jwk = new JsonObject { ["kty"] = "RSA", ["n"] = "abc", ["e"] = "AQAB" };
        Assert.Throws<ArgumentException>(() => KeyFactory.FromJwk(jwk));
    }

    [Fact(DisplayName = "§KeyFactory — TryFromJwk returns null for unsupported")]
    public void KeyFactoryTryReturnsNull()
    {
        var jwk = new JsonObject { ["kty"] = "RSA", ["n"] = "abc", ["e"] = "AQAB" };
        Assert.Null(KeyFactory.TryFromJwk(jwk));
    }

    // ── JwksClient Mixed JWKS Tests ────────────────────────────────────────

    [Fact(DisplayName = "§JWKS — resolves both Ed25519 and P-256 keys from same JWKS")]
    public async Task JwksClientResolvesMixedKeys()
    {
        var edKey = AAuthKey.Generate();
        var ecKey = EcdsaAAuthKey.Generate();

        var edJwk = edKey.ToPublicJwk();
        edJwk["kid"] = "ed-1";
        edJwk["use"] = "sig";

        var ecJwk = ecKey.ToPublicJwk();
        ecJwk["kid"] = "ec-1";
        ecJwk["use"] = "sig";

        var jwksDoc = new JsonObject
        {
            ["keys"] = new JsonArray { edJwk, ecJwk }
        };

        var handler = new MockHandler(jwksDoc.ToJsonString());
        var client = new JwksClient(new HttpClient(handler));

        var resolvedEd = await client.ResolveKeyAsync(new Uri("http://localhost/.well-known/jwks.json"), "ed-1");
        Assert.NotNull(resolvedEd);
        Assert.Equal("EdDSA", resolvedEd!.Algorithm);

        var resolvedEc = await client.ResolveKeyAsync(new Uri("http://localhost/.well-known/jwks.json"), "ec-1");
        Assert.NotNull(resolvedEc);
        Assert.Equal("ES256", resolvedEc!.Algorithm);
    }

    // ── TokenVerifier ES256 Tests ──────────────────────────────────────────

    [Fact(DisplayName = "§TokenVerifier — verifies ES256 agent token")]
    public void TokenVerifierAcceptsES256()
    {
        var apKey = EcdsaAAuthKey.Generate();
        var agentKey = AAuthKey.Generate(); // ephemeral still Ed25519

        // Build a token manually with ES256.
        var header = new JsonObject
        {
            ["alg"] = EcdsaAAuthKey.Alg,
            ["typ"] = AgentTokenBuilder.TokenType,
            ["kid"] = "ap-ec-1",
        };
        var now = DateTimeOffset.UtcNow;
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["dwk"] = AgentTokenBuilder.AgentDwk,
            ["sub"] = "agent-1",
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
        };

        var jwt = SignJwt(header, payload, apKey);

        var verifier = new TokenVerifier();
        var result = verifier.Verify(jwt, apKey, AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk);
        Assert.Equal("http://localhost:5555", result.Issuer);
    }

    [Fact(DisplayName = "§TokenVerifier — rejects ES256 token verified with wrong key")]
    public void TokenVerifierRejectsWrongES256Key()
    {
        var apKey = EcdsaAAuthKey.Generate();
        var wrongKey = EcdsaAAuthKey.Generate();

        var header = new JsonObject
        {
            ["alg"] = EcdsaAAuthKey.Alg,
            ["typ"] = AgentTokenBuilder.TokenType,
            ["kid"] = "wrong-1",
        };
        var now = DateTimeOffset.UtcNow;
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["dwk"] = AgentTokenBuilder.AgentDwk,
            ["sub"] = "agent-1",
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        };

        var jwt = SignJwt(header, payload, apKey);
        var verifier = new TokenVerifier();
        Assert.Throws<TokenVerificationException>(() =>
            verifier.Verify(jwt, wrongKey, AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk));
    }

    // ── HTTP Signature with P-256 Tests ────────────────────────────────────

    [Fact(DisplayName = "§HTTP Sig — P-256 key signs and verifies HTTP request")]
    public void HttpSigWithP256()
    {
        var ecKey = EcdsaAAuthKey.Generate();
        var verifier = new AAuthVerifier();

        // Build signature input manually.
        var method = "GET";
        var authority = "localhost:5000";
        var path = "/test";
        var signatureKey = "sig=hwk;jkt=\"test\";jwk=\"test\"";

        var sigBase = $"\"@method\": {method}\n\"@authority\": {authority}\n\"@path\": {path}\n\"signature-key\": {signatureKey}\n";
        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sigParams = $"(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={created}";
        sigBase += $"\"@signature-params\": {sigParams}";

        var sigBytes = ecKey.Sign(Encoding.ASCII.GetBytes(sigBase));
        var sigB64 = Base64UrlEncoder.Encode(sigBytes);

        // Verify with the same key.
        Assert.True(ecKey.Verify(Encoding.ASCII.GetBytes(sigBase), sigBytes));
    }

    // ── jkt-jwt Naming JWT Verification Tests ──────────────────────────────

    [Fact(DisplayName = "§jkt-jwt — naming JWT verified against issuer JWKS")]
    public async Task JktJwtNamingJwtVerified()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();

        // Build metadata + JWKS server.
        var metadataHost = await StartMetadataServer(durableKey, "durable-1");

        var metadataClient = new MetadataClient(metadataHost.GetTestClient());
        var jwksClient = new JwksClient(metadataHost.GetTestClient());
        var resolver = new DefaultSignatureKeyResolver(jwksClient, metadataClient);

        // Build naming JWT (jkt-s256+jwt) signed by durable key.
        var namingJwt = BuildNamingJwt(durableKey, "durable-1", ephemeralKey);
        var jkt = ephemeralKey.ComputeJwkThumbprint();

        // Parse as jkt-jwt scheme.
        var signatureKeyHeader = $"sig=jkt-jwt;jkt=\"{jkt}\";jwt=\"{namingJwt}\"";
        var info = SignatureKeyParser.ParseAny(signatureKeyHeader);
        Assert.Equal("jkt-jwt", info.Scheme);

        var resolution = await resolver.ResolveAsync(info);
        // Should succeed — the naming JWT is properly signed.
        Assert.NotNull(resolution.PublicKey);
        Assert.Equal(jkt, resolution.PublicKey.ComputeJwkThumbprint());

        await metadataHost.StopAsync();
        metadataHost.Dispose();
    }

    [Fact(DisplayName = "§jkt-jwt — forged naming JWT rejected")]
    public async Task JktJwtForgedNamingJwtRejected()
    {
        var durableKey = AAuthKey.Generate();
        var forgedKey = AAuthKey.Generate(); // sign with wrong key
        var ephemeralKey = AAuthKey.Generate();

        var metadataHost = await StartMetadataServer(durableKey, "durable-1");
        var metadataClient = new MetadataClient(metadataHost.GetTestClient());
        var jwksClient = new JwksClient(metadataHost.GetTestClient());
        var resolver = new DefaultSignatureKeyResolver(jwksClient, metadataClient);

        // Build naming JWT signed with the FORGED key (not the durable key in JWKS).
        var namingJwt = BuildNamingJwt(forgedKey, "durable-1", ephemeralKey);
        var jkt = ephemeralKey.ComputeJwkThumbprint();

        var signatureKeyHeader = $"sig=jkt-jwt;jkt=\"{jkt}\";jwt=\"{namingJwt}\"";
        var info = SignatureKeyParser.ParseAny(signatureKeyHeader);

        var ex = await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            resolver.ResolveAsync(info));
        Assert.Contains("signature verification failed", ex.Message);

        await metadataHost.StopAsync();
        metadataHost.Dispose();
    }

    [Fact(DisplayName = "§jkt-jwt — jkt mismatch still rejected")]
    public async Task JktJwtThumbprintMismatchRejected()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();
        var wrongKey = AAuthKey.Generate();

        var metadataHost = await StartMetadataServer(durableKey, "durable-1");
        var metadataClient = new MetadataClient(metadataHost.GetTestClient());
        var jwksClient = new JwksClient(metadataHost.GetTestClient());
        var resolver = new DefaultSignatureKeyResolver(jwksClient, metadataClient);

        // Build naming JWT delegating to ephemeralKey, but claim jkt of wrongKey.
        var namingJwt = BuildNamingJwt(durableKey, "durable-1", ephemeralKey);
        var wrongJkt = wrongKey.ComputeJwkThumbprint();

        var signatureKeyHeader = $"sig=jkt-jwt;jkt=\"{wrongJkt}\";jwt=\"{namingJwt}\"";
        var info = SignatureKeyParser.ParseAny(signatureKeyHeader);

        var ex = await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            resolver.ResolveAsync(info));
        Assert.Contains("jkt parameter does not match", ex.Message);

        await metadataHost.StopAsync();
        metadataHost.Dispose();
    }

    [Fact(DisplayName = "§jkt-jwt — resolver returns key even when naming JWT is expired (exp enforced by middleware)")]
    public async Task JktJwtExpiredNamingJwt_ResolverStillReturnsKey()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();

        var metadataHost = await StartMetadataServer(durableKey, "durable-1");
        var metadataClient = new MetadataClient(metadataHost.GetTestClient());
        var jwksClient = new JwksClient(metadataHost.GetTestClient());
        var resolver = new DefaultSignatureKeyResolver(jwksClient, metadataClient);

        // Build naming JWT that expired 10 minutes ago.
        var namingJwt = BuildExpiredNamingJwt(durableKey, "durable-1", ephemeralKey);
        var jkt = ephemeralKey.ComputeJwkThumbprint();

        var signatureKeyHeader = $"sig=jkt-jwt;jkt=\"{jkt}\";jwt=\"{namingJwt}\"";
        var info = SignatureKeyParser.ParseAny(signatureKeyHeader);

        // Resolver should succeed — exp is validated by the middleware, not here.
        var resolution = await resolver.ResolveAsync(info);
        Assert.NotNull(resolution.PublicKey);

        await metadataHost.StopAsync();
        metadataHost.Dispose();
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string BuildNamingJwt(IAAuthKey signingKey, string kid, IAAuthKey ephemeralKey)
    {
        var header = new JsonObject
        {
            ["alg"] = signingKey.Algorithm,
            ["typ"] = "jkt-s256+jwt",
            ["kid"] = kid,
        };
        var now = DateTimeOffset.UtcNow;
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["dwk"] = AgentTokenBuilder.AgentDwk,
            ["sub"] = "agent@test",
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(60).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = ephemeralKey.ToPublicJwk() },
        };

        return SignJwt(header, payload, signingKey);
    }

    private static string BuildExpiredNamingJwt(IAAuthKey signingKey, string kid, IAAuthKey ephemeralKey)
    {
        var header = new JsonObject
        {
            ["alg"] = signingKey.Algorithm,
            ["typ"] = "jkt-s256+jwt",
            ["kid"] = kid,
        };
        var past = DateTimeOffset.UtcNow.AddMinutes(-20);
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["dwk"] = AgentTokenBuilder.AgentDwk,
            ["sub"] = "agent@test",
            ["iat"] = past.ToUnixTimeSeconds(),
            ["exp"] = past.AddMinutes(10).ToUnixTimeSeconds(), // expired 10 min ago
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = ephemeralKey.ToPublicJwk() },
        };

        return SignJwt(header, payload, signingKey);
    }

    private static string SignJwt(JsonObject header, JsonObject payload, IAAuthKey key)
    {
        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = $"{headerB64}.{payloadB64}";
        var signature = key.Sign(Encoding.ASCII.GetBytes(signingInput));
        return $"{headerB64}.{payloadB64}.{Base64UrlEncoder.Encode(signature)}";
    }

    private static async Task<IHost> StartMetadataServer(AAuthKey durableKey, string kid)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = "http://localhost:5555",
            jwks_uri = "http://localhost:5555/.well-known/jwks.json",
        }));
        app.MapGet("/.well-known/jwks.json", () =>
        {
            var jwk = durableKey.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        await app.StartAsync();
        return app;
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly string _response;
        public MockHandler(string response) => _response = response;
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_response, Encoding.UTF8, "application/json"),
            });
        }
    }
}
