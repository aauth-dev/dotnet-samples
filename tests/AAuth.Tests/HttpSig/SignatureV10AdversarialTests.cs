using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Tests.HttpSig;

public class SignatureV10AdversarialTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);

    [Theory]
    [InlineData("unknown-typ", "invalid_jwt")]
    [InlineData("forged", "invalid_jwt")]
    [InlineData("forged-invalid-cnf", "invalid_jwt")]
    [InlineData("missing-exp", "invalid_jwt")]
    [InlineData("expired", "expired_jwt")]
    [InlineData("private-cnf", "invalid_key")]
    [InlineData("missing-alg", "unsupported_algorithm")]
    [InlineData("numeric-jti", "invalid_jwt")]
    [InlineData("issuer-missing", "issuer_missing")]
    [InlineData("issuer-mismatch", "issuer_mismatch")]
    public async Task InvalidAssertionsNeverAuthenticate(string mutation, string expectedError)
    {
        var issuerKey = AAuthKey.Generate();
        var key = EcdsaAAuthKey.Generate();
        var header = new JsonObject { ["typ"] = AgentTokenBuilder.TokenType, ["alg"] = "Ed25519", ["kid"] = "issuer" };
        var confirmation = key.ToPublicJwk();
        var payload = new JsonObject { ["iss"] = "https://issuer.example", ["dwk"] = "aauth-agent.json", ["sub"] = "aauth:wire@example.com",
            ["iat"] = Now.ToUnixTimeSeconds(), ["exp"] = Now.AddMinutes(1).ToUnixTimeSeconds(), ["cnf"] = new JsonObject { ["jwk"] = confirmation } };
        if (mutation == "unknown-typ") header["typ"] = "unregistered+jwt";
        if (mutation == "missing-exp") payload.Remove("exp");
        if (mutation == "expired") payload["exp"] = Now.AddMinutes(-2).ToUnixTimeSeconds();
        if (mutation == "numeric-jti") payload["jti"] = 123;
        if (mutation is "missing-alg" or "forged-invalid-cnf") confirmation.Remove("alg");
        if (mutation == "private-cnf") payload["cnf"] = new JsonObject { ["jwk"] = key.ToPrivateJwk() };
        var jwt = SignatureV10WireTests.Jwt(header, payload, mutation.StartsWith("forged") ? AAuthKey.Generate() : issuerKey);
        using var http = new InProcessHttpClient(new Discovery(issuerKey, mutation));
        var context = Signed(key, "sig=jwt;jwt=\"" + jwt + "\"");
        await Middleware(http).InvokeAsync(context);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("error=" + expectedError, context.Response.Headers["Signature-Error"].ToString());
        Assert.Null(context.Features.Get<AAuthVerificationResult>());
        if (expectedError == "unsupported_algorithm")
            Assert.Equal("Ed25519, ES256", context.Response.Headers["Accept-Signature-Alg"].ToString());
    }

    [Theory]
    [InlineData(false, 401)]
    [InlineData(true, 400)]
    public async Task UnknownSchemeNegotiatesAccordingToProfile(bool generic, int status)
    {
        var key = AAuthKey.Generate();
        var context = Signed(key, "sig=unregistered;flag");
        await Middleware(null, new() { GenericSignatureKeys = generic, Clock = () => Now }).InvokeAsync(context);
        Assert.Equal(status, context.Response.StatusCode);
        Assert.Equal("error=unsupported_scheme", context.Response.Headers["Signature-Error"].ToString());
        Assert.Equal("jwt", context.Response.Headers["Accept-Signature-Scheme"].ToString());
    }

    [Fact]
    public async Task AuthorizationDenialHasNoSignatureHeaders()
    {
        var key = AAuthKey.Generate();
        var context = Signed(key, SignatureKeyHeader.FormatHwk(key));
        await Middleware(null, AAuthVerificationOptions.Generic(() => Now), deny: true).InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Signature-Error"));
        Assert.False(context.Response.Headers.ContainsKey("Accept-Signature-Scheme"));
        Assert.False(context.Response.Headers.ContainsKey("Accept-Signature-Alg"));
    }

    [Fact]
    public void ConflictingKeyIdFails()
    {
        var key = AAuthKey.Generate();
        var context = Signed(key, SignatureKeyHeader.FormatHwk(key), ";keyid=\"wrong\"");
        var failure = Assert.Throws<AAuthVerificationException>(() => new AAuthVerifier { Clock = () => Now }.Verify("POST", "resource.example", "/wire",
            context.Request.Headers["Signature-Key"]!, context.Request.Headers["Signature-Input"]!, context.Request.Headers["Signature"]!, key));
        Assert.Equal(SignatureErrorCode.InvalidKey, failure.Code);
    }

    [Theory]
    [InlineData("exp")]
    [InlineData("iat")]
    [InlineData("future-iat")]
    [InlineData("alg")]
    public void NamingJwtRequiresClaimsAndCorrectAlgorithm(string mutation)
    {
        var durable = EcdsaAAuthKey.Generate();
        var key = AAuthKey.Generate();
        var header = new JsonObject { ["typ"] = "jkt-s256+jwt", ["alg"] = "ES256", ["jwk"] = durable.ToPublicJwk() };
        var payload = new JsonObject { ["iss"] = "urn:jkt:sha-256:" + durable.ComputeJwkThumbprint(), ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(), ["cnf"] = new JsonObject { ["jwk"] = key.ToPublicJwk() } };
        if (mutation == "future-iat") payload["iat"] = Now.AddMinutes(1).ToUnixTimeSeconds();
        else if (mutation == "alg") header["alg"] = "Ed25519";
        else payload.Remove(mutation);
        var jwt = SignatureV10WireTests.Jwt(header, payload, durable);
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<AAuthVerificationException>(() => NamingTokenVerifier.Verify(jwt, Now, TimeSpan.Zero)).Code);
    }

    [Fact]
    public void SelfJwtForbidsEvenNullConfirmation()
    {
        var key = AAuthKey.Generate();
        var jwt = SignatureV10WireTests.Jwt(new JsonObject { ["alg"] = "Ed25519" }, new JsonObject { ["cnf"] = null }, key);
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<AAuthVerificationException>(() =>
            SignatureKeyParser.ParseAny("sig=self-jwt;jwt=\"" + jwt + "\"")).Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CoveredDigestAuthenticatesActualBody(bool tampered)
    {
        var key = AAuthKey.Generate();
        var carrier = SignatureKeyHeader.FormatHwk(key);
        var body = "{\"value\":1}";
        var digest = "sha-256=:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body))) + ":";
        var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-digest\");created=1800000000";
        var signatureBase = $"\"@method\": POST\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": {carrier}\n\"content-digest\": {digest}\n\"@signature-params\": {parameters}";
        var context = Signed(key, carrier);
        context.Request.Headers["Content-Digest"] = digest;
        context.Request.Headers["Signature-Input"] = "sig=" + parameters;
        context.Request.Headers["Signature"] = "sig=:" + Convert.ToBase64String(key.Sign(Encoding.ASCII.GetBytes(signatureBase))) + ":";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(tampered ? "{\"value\":2}" : body));
        await Middleware(null, AAuthVerificationOptions.Generic(() => Now)).InvokeAsync(context);
        Assert.Equal(tampered ? 401 : 204, context.Response.StatusCode);
        Assert.Equal(0, context.Request.Body.Position);
    }

    [Fact]
    public async Task MultipleFieldLinesSelectSameLabel()
    {
        var key = AAuthKey.Generate();
        var carrier = "ignored=unknown, " + SignatureKeyHeader.FormatHwk(key);
        var context = Signed(key, carrier);
        context.Request.Headers["Signature-Key"] = new Microsoft.Extensions.Primitives.StringValues(["ignored=unknown", SignatureKeyHeader.FormatHwk(key)]);
        context.Request.Headers.Append("Signature-Input", "ignored=(\"@method\");created=1");
        context.Request.Headers.Append("Signature", "ignored=:AQID:");
        await Middleware(null, AAuthVerificationOptions.Generic(() => Now)).InvokeAsync(context);
        Assert.Equal(204, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("\"x\";sf;bs", "x", "a=1")]
    [InlineData("\"x\";sf", "x", "a=1")]
    [InlineData("\"@unknown\"", "@unknown", "attacker-controlled")]
    [InlineData("\"x\"", "x", "injected\nline")]
    [InlineData("\"x\";sf;key=\"a\" \"x\";key=\"a\";sf", "x", "a=1")]
    public void InvalidComponentSemanticsReject(string component, string name, string value)
    {
        var key = AAuthKey.Generate();
        var input = "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\" " + component + ");created=1800000000";
        var error = Assert.Throws<AAuthVerificationException>(() => new AAuthVerifier { Clock = () => Now }.Verify("POST", "resource.example", "/wire",
            SignatureKeyHeader.FormatHwk(key), input, "sig=:AQID:", key, fields: new Dictionary<string, string> { [name] = value }));
        Assert.Equal(SignatureErrorCode.InvalidInput, error.Code);
    }

    [Theory]
    [InlineData("\"example\";sf", "a=1, b=2;x=1;y=2, c=(a b c)", false)]
    [InlineData("\"example\";key=\"c\"", "(a b c)", false)]
    [InlineData("\"example\";bs", ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:", true)]
    public void StructuredFieldVectorsHaveExactRfcSerialization(string component, string expected, bool binary)
    {
        var key = AAuthKey.Generate();
        var carrier = SignatureKeyHeader.FormatHwk(key);
        var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\" " + component + ");created=1800000000";
        var signatureBase = $"\"@method\": POST\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": {carrier}\n{component}: {expected}\n\"@signature-params\": {parameters}";
        var signature = "sig=:" + Convert.ToBase64String(key.Sign(Encoding.ASCII.GetBytes(signatureBase))) + ":";
        new AAuthVerifier { Clock = () => Now, StructuredFieldTypes = new Dictionary<string, StructuredFieldType> { ["example"] = StructuredFieldType.Dictionary } }
            .Verify("POST", "resource.example", "/wire", carrier, "sig=" + parameters, signature, key,
                fields: new Dictionary<string, string> { ["example"] = binary ? "value, with, lots, of, commas" : " a=1,    b=2;x=1;y=2, c=(a   b   c) " },
                fieldValues: binary ? new Dictionary<string, string[]> { ["example"] = ["value, with, lots", "of, commas"] } : null);
    }

    private static AAuthVerificationMiddleware Middleware(HttpClient? http, AAuthVerificationOptions? options = null, bool deny = false) => new(
        context => { context.Response.StatusCode = deny ? 403 : 204; return Task.CompletedTask; },
        new AAuthVerifier { Clock = () => Now }, new DefaultSignatureKeyResolver(),
        http is null ? null : new MetadataClient(http), http is null ? null : new JwksClient(http),
        options ?? new() { Clock = () => Now, ClockSkew = TimeSpan.Zero });

    private static DefaultHttpContext Signed(IAAuthKey key, string carrier, string extra = "")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST"; context.Request.Host = new HostString("resource.example"); context.Request.Path = "/wire";
        var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1800000000" + extra;
        var signatureBase = "\"@method\": POST\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": " + carrier + "\n\"@signature-params\": " + parameters;
        context.Request.Headers["Signature-Key"] = carrier;
        context.Request.Headers["Signature-Input"] = "sig=" + parameters;
        context.Request.Headers["Signature"] = "sig=:" + Convert.ToBase64String(key.Sign(Encoding.ASCII.GetBytes(signatureBase))) + ":";
        return context;
    }

    private sealed class Discovery(IAAuthKey key, string mutation) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var jwk = key.ToPublicJwk(); jwk["kid"] = "issuer";
            var document = request.RequestUri!.AbsolutePath == "/keys"
                ? new JsonObject { ["keys"] = new JsonArray(jwk) }
                : new JsonObject { ["issuer"] = mutation == "issuer-mismatch" ? "https://forged.example" : "https://issuer.example", ["jwks_uri"] = "https://issuer.example/keys" };
            if (mutation == "issuer-missing") document.Remove("issuer");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(document) });
        }
    }
}