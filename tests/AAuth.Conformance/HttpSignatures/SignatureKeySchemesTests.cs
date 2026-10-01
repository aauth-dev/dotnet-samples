using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for Signature-Key header scheme support per §4.
/// </summary>
public class SignatureKeySchemesTests
{
    private static readonly DateTimeOffset FixedClock = DateTimeOffset.FromUnixTimeSeconds(1800000000);

    [Fact(DisplayName = "§4 — jwt scheme formats correctly")]
    public void JwtScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJwt("eyJ.payload.sig");
        Assert.Equal("sig=jwt;jwt=\"eyJ.payload.sig\"", header);
    }

    [Fact(DisplayName = "§4 — hwk scheme formats with jkt and inline jwk parameters")]
    public void HwkScheme_FormatsCorrectly()
    {
        var key = AAuthKey.Generate();
        var jkt = key.ComputeJwkThumbprint();
        var jwkJson = System.Text.Json.JsonSerializer.Serialize(key.ToPublicJwk());
        var jwkB64 = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(jwkJson);
        var header = SignatureKeyHeader.FormatHwk(key);
        Assert.StartsWith("sig=hwk;kty=\"OKP\"", header);
        Assert.Contains(";alg=\"Ed25519\"", header);
    }

    [Fact(DisplayName = "§4 — jwks_uri scheme formats with uri and kid parameters")]
    public void JwksUriScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJwksUri("https://example.com", "config", "key-1");
        Assert.Equal("sig=jwks_uri;id=\"https://example.com\";dwk=\"config\";kid=\"key-1\"", header);
    }

    [Fact(DisplayName = "§4 — jkt-jwt scheme formats with a single jwt parameter")]
    public void JktJwtScheme_FormatsCorrectly()
    {
        var header = SignatureKeyHeader.FormatJktJwt("eyJ.payload.sig");
        Assert.Equal("sig=jkt-jwt;jwt=\"eyJ.payload.sig\"", header);
    }

    [Fact(DisplayName = "§4 — ParseAny handles jwt scheme")]
    public async Task ParseAny_JwtScheme()
    {
        // Build a minimal valid JWT with cnf.jwk
        var key = AAuthKey.Generate();
        var agentToken = await new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            Key = key,
            KeyId = "k1",
            PersonServer = "https://ps.example",
        }.BuildAsync();
        var headerValue = SignatureKeyHeader.FormatJwt(agentToken);

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jwt", info.Scheme);
        Assert.Null(info.ConfirmationKey);
        Assert.NotNull(info.Jwt);
        Assert.NotNull(info.Payload);
    }

    [Fact(DisplayName = "§4 — ParseAny handles hwk scheme with inline key")]
    public void ParseAny_HwkScheme()
    {
        var key = AAuthKey.Generate();
        var provider = new HwkSignatureKeyProvider(key);
        var headerValue = provider.GetSignatureKeyHeader();

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("hwk", info.Scheme);
        Assert.Equal(key.ComputeJwkThumbprint(), info.Jkt);
        Assert.NotNull(info.ConfirmationKey); // Inline per spec
        Assert.Equal(key.ComputeJwkThumbprint(), info.ConfirmationKey.ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "§4 — ParseAny handles jwks_uri scheme")]
    public void ParseAny_JwksUriScheme()
    {
        var headerValue = SignatureKeyHeader.FormatJwksUri("https://example.com", "config", "kid1");

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jwks_uri", info.Scheme);
        Assert.Equal("https://example.com", info.Identifier);
        Assert.Equal("kid1", info.Kid);
    }

    [Fact(DisplayName = "§4 — ParseAny handles jkt-jwt scheme (self-issued naming JWT)")]
    public async Task ParseAny_JktJwtScheme()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();
        var namingJwt = await AAuth.Agent.NamingJwtBuilder.BuildAsync(durableKey, ephemeralKey);
        var headerValue = SignatureKeyHeader.FormatJktJwt(namingJwt);

        var info = SignatureKeyParser.ParseAny(headerValue);
        Assert.Equal("jkt-jwt", info.Scheme);
        // The reported pseudonym is the DURABLE key's thumbprint (§7.1).
        Assert.Null(info.Jkt);
        // The confirmation key is the ephemeral key (cnf.jwk).
        var verified = NamingTokenVerifier.Verify(info.Jwt!, DateTimeOffset.UtcNow, TimeSpan.Zero);
        Assert.Equal(ephemeralKey.ComputeJwkThumbprint(), verified.ConfirmationKey.ComputeJwkThumbprint());
        Assert.NotNull(info.Jwt);
        Assert.NotNull(info.Payload);
    }

    [Fact(DisplayName = "§3.4 — ParseAny rejects a jkt-jwt header carrying a stray jkt parameter")]
    public async Task ParseAny_JktJwtScheme_RejectsStrayJktParameter()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();
        var namingJwt = await AAuth.Agent.NamingJwtBuilder.BuildAsync(durableKey, ephemeralKey);
        // The retired non-conformant format carried a jkt parameter.
        var headerValue = $"sig=jkt-jwt;jkt=\"{ephemeralKey.ComputeJwkThumbprint()}\";jwt=\"{namingJwt}\"";

        Assert.Throws<AAuthVerificationException>(() => SignatureKeyParser.ParseAny(headerValue));
    }

    [Fact(DisplayName = "RFC7515 §4.1.11 — jkt-jwt rejects unsupported crit")]
    public async Task JktJwt_RejectsCriticalJoseHeader()
    {
        var durableKey = AAuthKey.Generate();
        var ephemeralKey = AAuthKey.Generate();
        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Ed25519Algorithm,
            ["typ"] = AAuthConstants.TokenTypes.JktS256Jwt,
            ["jwk"] = durableKey.ToPublicJwk(),
            ["crit"] = new JsonArray("x"),
            ["x"] = true,
        };
        var payload = new JsonObject
        {
            ["iss"] = AAuthConstants.JktThumbprintUrnPrefix + durableKey.ComputeJwkThumbprint(),
            ["iat"] = FixedClock.ToUnixTimeSeconds(),
            ["exp"] = FixedClock.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = "naming-token",
            ["cnf"] = new JsonObject { ["jwk"] = ephemeralKey.ToPublicJwk() },
        };
        var jwt = await SignJwtAsync(header, payload, durableKey);

        var failure = Assert.Throws<AAuthVerificationException>(() =>
            NamingTokenVerifier.Verify(jwt, FixedClock, TimeSpan.Zero));

        Assert.Equal(SignatureErrorCode.InvalidJwt, failure.Code);
    }

    [Theory(DisplayName = "RFC7515 §4.1.11 — companion jwt/self-jwt reject unsupported crit")]
    [InlineData(AAuthConstants.Schemes.Jwt)]
    [InlineData(AAuthConstants.Schemes.SelfJwt)]
    public async Task CompanionJwt_RejectsCriticalJoseHeader(string scheme)
    {
        var issuerKey = AAuthKey.Generate();
        var httpKey = AAuthKey.Generate();
        var jwt = await BuildCompanionJwtAsync(issuerKey, httpKey, FixedClock.AddMinutes(5),
            omitIssuerMetadata: scheme == AAuthConstants.Schemes.Jwt,
            mutateHeader: header =>
            {
                header["crit"] = new JsonArray("x");
                header["x"] = true;
            });
        var companion = new CompanionVerifier(issuerKey, "app-issuer", scheme);
        var resolver = new DefaultSignatureKeyResolver(
            tokenVerifier: new TokenVerifier { TimeProvider = new FakeTimeProvider(FixedClock), ClockSkew = TimeSpan.FromSeconds(30) },
            tokenVerifiers: [companion]);

        var failure = await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            resolver.ResolveAsync(SignatureKeyParser.ParseAny(scheme == AAuthConstants.Schemes.SelfJwt
                ? SignatureKeyHeader.FormatSelfJwt(jwt)
                : SignatureKeyHeader.FormatJwt(jwt))));

        Assert.Equal(SignatureErrorCode.InvalidJwt, failure.Code);
        Assert.Equal(0, companion.ResolveCalls);
        Assert.Equal(0, companion.VerifyCalls);
    }

    [Fact(DisplayName = "Signature-Key §3.8 — companion jwt without iss/dwk resolves issuer key through seam")]
    public async Task JwtCompanionVerifier_ResolvesIssuerKeyWithoutIssOrDwk()
    {
        var issuerKey = AAuthKey.Generate();
        var httpKey = AAuthKey.Generate();
        var jwt = await BuildCompanionJwtAsync(issuerKey, httpKey, FixedClock.AddMinutes(5), omitIssuerMetadata: true);
        var companion = new CompanionVerifier(issuerKey, "app-issuer");
        var resolver = new DefaultSignatureKeyResolver(
            tokenVerifier: new TokenVerifier { TimeProvider = new FakeTimeProvider(FixedClock), ClockSkew = TimeSpan.FromSeconds(30) },
            tokenVerifiers: [companion]);

        var resolution = await resolver.ResolveAsync(SignatureKeyParser.ParseAny(SignatureKeyHeader.FormatJwt(jwt)));

        Assert.Equal(1, companion.ResolveCalls);
        Assert.Equal(1, companion.VerifyCalls);
        Assert.Equal(httpKey.ComputeJwkThumbprint(), resolution.PublicKey.ComputeJwkThumbprint());
        Assert.Equal("app-issuer", resolution.VerifiedIdentifier);
    }

    [Fact(DisplayName = "Signature-Key §3.8 — companion jwt expiration has zero skew")]
    public async Task JwtCompanionVerifier_RejectsExpiredWithoutClockSkew()
    {
        var issuerKey = AAuthKey.Generate();
        var httpKey = AAuthKey.Generate();
        var jwt = await BuildCompanionJwtAsync(issuerKey, httpKey, FixedClock.AddSeconds(-20), omitIssuerMetadata: true);
        var companion = new CompanionVerifier(issuerKey, "app-issuer");
        var resolver = new DefaultSignatureKeyResolver(
            tokenVerifier: new TokenVerifier { TimeProvider = new FakeTimeProvider(FixedClock), ClockSkew = TimeSpan.FromSeconds(30) },
            tokenVerifiers: [companion]);

        var failure = await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            resolver.ResolveAsync(SignatureKeyParser.ParseAny(SignatureKeyHeader.FormatJwt(jwt))));

        Assert.Equal(SignatureErrorCode.ExpiredJwt, failure.Code);
        Assert.Equal(0, companion.ResolveCalls);
        Assert.Equal(0, companion.VerifyCalls);
    }

    private static Task<string> BuildCompanionJwtAsync(IAAuthSigner issuerKey, IAAuthKey httpKey,
        DateTimeOffset expiresAt, bool omitIssuerMetadata, Action<JsonObject>? mutateHeader = null)
    {
        var header = new JsonObject
        {
            ["alg"] = issuerKey.Algorithm,
            ["typ"] = CompanionVerifier.CompanionType,
            ["kid"] = "app-key",
        };
        mutateHeader?.Invoke(header);
        var payload = new JsonObject
        {
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["cnf"] = new JsonObject { ["jwk"] = httpKey.ToPublicJwk() },
        };
        if (!omitIssuerMetadata)
        {
            payload["iss"] = "https://app.example";
            payload["dwk"] = "app.json";
        }
        return SignJwtAsync(header, payload, issuerKey);
    }

    private static async Task<string> SignJwtAsync(JsonObject header, JsonObject payload, IAAuthSigner key)
    {
        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var input = $"{headerB64}.{payloadB64}";
        return $"{input}.{Base64UrlEncoder.Encode(await key.SignAsync(Encoding.ASCII.GetBytes(input)))}";
    }

    private sealed class CompanionVerifier(IAAuthKey issuerKey, string issuer, string scheme = AAuthConstants.Schemes.Jwt) : ISignatureTokenVerifier
    {
        public const string CompanionType = "app+jwt";
        public string Scheme => scheme;
        public string TokenType => CompanionType;
        public int ResolveCalls { get; private set; }
        public int VerifyCalls { get; private set; }

        public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken)
        {
            ResolveCalls++;
            Assert.Null(context.Issuer);
            Assert.Null(context.Dwk);
            Assert.Null(context.ExpectedDwk);
            return ValueTask.FromResult<IAAuthKey?>(issuerKey);
        }

        public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken cancellationToken)
        {
            VerifyCalls++;
            Assert.Equal(issuerKey.ComputeJwkThumbprint(), context.IssuerKey.ComputeJwkThumbprint());
            return Task.FromResult(new TokenVerifier.VerifiedToken(context.Header, context.Payload, issuer, context.TokenType));
        }
    }
}
