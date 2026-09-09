using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tests.HttpSig;

public class SignatureV10WireTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);

    public static IEnumerable<object[]> Schemes => new[] { "hwk", "jwt", "jkt-jwt", "jwks_uri", "jwks", "self-jwt" }
        .SelectMany(scheme => new[] { new object[] { scheme, false }, new object[] { scheme, true } });

    [Theory]
    [MemberData(nameof(Schemes))]
    public async Task IndependentWireVerifiesAllSchemesAndAlgorithms(string scheme, bool ecdsa)
    {
        IAAuthKey key = ecdsa ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();
        IAAuthKey issuerKey = ecdsa ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();
        var jwk = key.ToPublicJwk();
        var issuer = "https://issuer.example";
        var payload = new JsonObject { ["iss"] = issuer, ["dwk"] = "aauth-agent.json", ["sub"] = "aauth:wire@example.com",
            ["iat"] = Now.ToUnixTimeSeconds(), ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds() };
        var header = new JsonObject { ["typ"] = AgentTokenBuilder.TokenType, ["kid"] = "issuer-key", ["alg"] = issuerKey.Algorithm };
        var wire = "";
        switch (scheme)
        {
            case "hwk":
                wire = $"chosen=hwk;kty=\"{jwk["kty"]}\";crv=\"{jwk["crv"]}\";x=\"{jwk["x"]}\";alg=\"{jwk["alg"]}\""
                    + (ecdsa ? $";y=\"{jwk["y"]}\"" : "");
                break;
            case "jwks_uri": wire = "chosen=jwks_uri;id=\"https://issuer.example\";dwk=\"aauth-agent.json\";kid=\"http-key\""; break;
            case "jwks": wire = "chosen=jwks;url=\"https://keys.example/distinct\";kid=\"http-key\""; break;
            default:
                if (scheme == "jkt-jwt")
                {
                    header["typ"] = "jkt-s256+jwt";
                    header["jwk"] = issuerKey.ToPublicJwk();
                    payload["iss"] = "urn:jkt:sha-256:" + issuerKey.ComputeJwkThumbprint();
                }
                if (scheme == "self-jwt")
                {
                    issuerKey = key;
                    header["typ"] = "test-event+jwt";
                    header["alg"] = key.Algorithm;
                }
                else payload["cnf"] = new JsonObject { ["jwk"] = jwk };
                wire = $"chosen={scheme};jwt=\"{Jwt(header, payload, issuerKey)}\"";
                break;
        }
        wire = "ignored=unregistered;flag, " + wire;
        using var http = new InProcessHttpClient(new DiscoveryHandler(issuerKey, key),
            policy: new AAuthEgressPolicy(crossOriginJwks: [("https://issuer.example", "https://keys.example")]));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http),
            new TokenVerifier { EgressPolicy = TestEgress.Policy, Clock = () => Now, ClockSkew = TimeSpan.Zero }, [new EventVerifier()]);
        var resolution = await resolver.ResolveAsync(SignatureKeyParser.ParseAny(wire, "chosen"));
        var parameters = "(\"@path\" \"content-type\" \"@method\" \"signature-key\" \"@authority\");created=1800000000;expires=1800000010;nonce=\"a\\\"b\\\\c\";alg=\"ignored\"";
        var signatureBase = $"\"@path\": /wire%2Fpath\n\"content-type\": application/json\n\"@method\": POST\n\"signature-key\": {wire}\n\"@authority\": resource.example\n\"@signature-params\": {parameters}";
        var signature = key.Sign(Encoding.ASCII.GetBytes(signatureBase));
        new AAuthVerifier { Clock = () => Now }.Verify("POST", "resource.example", "/wire%2Fpath", wire,
            "ignored=(\"@method\");created=1, chosen=" + parameters,
            "ignored=:AQID:, chosen=:" + Convert.ToBase64String(signature) + ":", resolution.PublicKey,
            label: "chosen", fields: new Dictionary<string, string> { ["content-type"] = "application/json" },
            requiredComponents: ["content-type"], keyId: resolution.KeyId);
        Assert.Equal(key.ComputeJwkThumbprint(), resolution.PublicKey.ComputeJwkThumbprint());
        Assert.Equal(scheme is "jwt" or "self-jwt", resolution.VerifiedToken is not null);
        if (scheme == "jwks_uri") Assert.Equal(issuer, resolution.VerifiedIdentifier);
        if (scheme == "jwks") Assert.Equal("https://keys.example/distinct", resolution.VerifiedIdentifier);
    }

    [Theory]
    [InlineData("sig=hwk;jkt=\"old\";jwk=\"old\"", SignatureErrorCode.InvalidKey)]
    [InlineData("sig=jwks_uri;uri=\"https://example.com/jwks\";kid=\"key\"", SignatureErrorCode.InvalidKey)]
    [InlineData("sig=unregistered", SignatureErrorCode.UnsupportedScheme)]
    [InlineData("other=hwk", SignatureErrorCode.InvalidRequest)]
    [InlineData("sig=hwk;kty=\"bad", SignatureErrorCode.InvalidRequest)]
    [InlineData("sig=hwk, sig=jwt", SignatureErrorCode.InvalidRequest)]
    public void LegacyMalformedAndUnknownCarriersAreTyped(string wire, SignatureErrorCode code)
        => Assert.Equal(code, Assert.Throws<AAuthVerificationException>(() => SignatureKeyParser.ParseAny(wire)).Code);

    [Theory]
    [InlineData("expires", 1799999999L)]
    [InlineData("created", 1800000100L)]
    public void InvalidSignatureTimesRejectBeforeKeyResolution(string parameter, long value)
    {
        var parameters = new Dictionary<string, long> { ["created"] = 1800000000, ["expires"] = 1800000001 };
        parameters[parameter] = value;
        var input = "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + parameters["created"] + ";expires=" + parameters["expires"];
        Assert.Equal(SignatureErrorCode.InvalidSignature, Assert.Throws<AAuthVerificationException>(() =>
            new AAuthVerifier { Clock = () => Now }.ValidateInput(input, "sig")).Code);
    }

    internal static string Jwt(JsonObject header, JsonObject payload, IAAuthKey key)
    {
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }

    [Fact]
    public void TwoRealSignaturesBindTheCompleteKeyDictionary()
    {
        IAAuthKey first = AAuthKey.Generate();
        IAAuthKey second = EcdsaAAuthKey.Generate();
        var carrier = SignatureKeyHeader.FormatHwk(first, "first") + ", " + SignatureKeyHeader.FormatHwk(second, "second");
        var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1800000000";
        var signatureBase = $"\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": {carrier}\n\"@signature-params\": {parameters}";
        var signatures = "first=:" + Convert.ToBase64String(first.Sign(Encoding.ASCII.GetBytes(signatureBase)))
            + ":, second=:" + Convert.ToBase64String(second.Sign(Encoding.ASCII.GetBytes(signatureBase))) + ":";
        var inputs = "first=" + parameters + ", second=" + parameters;
        var verifier = new AAuthVerifier { Clock = () => Now };
        verifier.Verify("GET", "resource.example", "/wire", carrier, inputs, signatures, first, label: "first");
        verifier.Verify("GET", "resource.example", "/wire", carrier, inputs, signatures, second, label: "second");
        Assert.Throws<AAuthVerificationException>(() => verifier.Verify("GET", "resource.example", "/wire",
            carrier.Replace("second=hwk", "second=unknown"), inputs, signatures, first, label: "first"));
    }

    private sealed class EventVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "self-jwt";
        public string TokenType => "test-event+jwt";
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(string jwt, IAAuthKey key, TokenVerifier verifier, CancellationToken ct) =>
            Task.FromResult(verifier.Verify(jwt, key, TokenType, "aauth-agent.json"));
    }

    private sealed class DiscoveryHandler(IAAuthKey issuerKey, IAAuthKey httpKey) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            JsonObject document;
            if (request.RequestUri!.AbsolutePath.StartsWith("/.well-known/"))
                document = new() { ["issuer"] = "https://issuer.example", ["jwks_uri"] = "https://keys.example/distinct" };
            else
            {
                var issuerJwk = issuerKey.ToPublicJwk(); issuerJwk["kid"] = "issuer-key";
                var httpJwk = httpKey.ToPublicJwk(); httpJwk["kid"] = "http-key";
                document = new() { ["keys"] = new JsonArray(new JsonObject { ["kid"] = "future", ["alg"] = "ML-DSA-65", ["kty"] = 42 }, issuerJwk, httpJwk) };
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(document.ToJsonString(), Encoding.UTF8, "application/json") });
        }
    }
}