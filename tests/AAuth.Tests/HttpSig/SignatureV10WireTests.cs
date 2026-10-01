using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tests.HttpSig;

public class SignatureV10WireTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
    private static readonly FakeTimeProvider Time = new(Now);

    public static IEnumerable<object[]> Schemes => new[] { "hwk", "jwt", "jkt-jwt", "jwks_uri", "jwks", "self-jwt" }
        .SelectMany(scheme => new[] { new object[] { scheme, false }, new object[] { scheme, true } });

    [Theory]
    [MemberData(nameof(Schemes))]
    public async Task IndependentWireVerifiesAllSchemesAndAlgorithms(string scheme, bool ecdsa)
    {
        IAAuthSigner key = ecdsa ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();
        IAAuthSigner issuerKey = ecdsa ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();
        var jwk = key.ToPublicJwk();
        var issuer = "https://issuer.example";
        var payload = new JsonObject { ["iss"] = issuer, ["dwk"] = "aauth-agent.json", ["sub"] = "aauth:wire@issuer.example", ["jti"] = "token-id",
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
                wire = $"chosen={scheme};jwt=\"{await JwtAsync(header, payload, issuerKey)}\"";
                break;
        }
        wire = "ignored=unregistered;flag, " + wire;
        using var http = new InProcessHttpClient(new DiscoveryHandler(issuerKey, key),
            policy: new AAuthEgressPolicy(crossOriginJwks: [("https://issuer.example", "https://keys.example")]));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http),
            new TokenVerifier { EgressPolicy = TestEgress.Policy, TimeProvider = Time, ClockSkew = TimeSpan.Zero }, [new EventVerifier()]);
        var resolution = await resolver.ResolveAsync(SignatureKeyParser.ParseAny(wire, "chosen"));
        var parameters = "(\"@path\" \"content-type\" \"@method\" \"signature-key\" \"@authority\");created=1800000000;expires=1800000010;nonce=\"a\\\"b\\\\c\";alg=\"ignored\"";
        var signatureBase = $"\"@path\": /wire%2Fpath\n\"content-type\": application/json\n\"@method\": POST\n\"signature-key\": {wire}\n\"@authority\": resource.example\n\"@signature-params\": {parameters}";
        var signature = await key.SignAsync(Encoding.ASCII.GetBytes(signatureBase));
        new AAuthVerifier { TimeProvider = Time }.Verify("POST", "resource.example", "/wire%2Fpath", wire,
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
    [InlineData("other=hwk", SignatureErrorCode.InvalidKey)]
    [InlineData("sig=hwk;kty=\"bad", SignatureErrorCode.InvalidKey)]
    [InlineData("sig=hwk, sig=jwt", SignatureErrorCode.InvalidKey)]
    public void LegacyMalformedAndUnknownCarriersAreTyped(string wire, SignatureErrorCode code)
        => Assert.Equal(code, Assert.Throws<AAuthVerificationException>(() => SignatureKeyParser.ParseAny(wire)).Code);

    [Theory]
    [InlineData("expires", 1799999999L, SignatureErrorCode.InvalidSignature)]
    [InlineData("created", 1799999939L, SignatureErrorCode.InvalidSignature)]
    [InlineData("created", 1800000061L, SignatureErrorCode.ClockSkew)]
    public void InvalidSignatureTimesRejectBeforeKeyResolution(string parameter, long value, SignatureErrorCode code)
    {
        var parameters = new Dictionary<string, long> { ["created"] = 1800000000, ["expires"] = 1800000100 };
        parameters[parameter] = value;
        var input = "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + parameters["created"] + ";expires=" + parameters["expires"];
        Assert.Equal(code, Assert.Throws<AAuthVerificationException>(() =>
            new AAuthVerifier { TimeProvider = Time }.ValidateInput(input, "sig")).Code);
    }

    [Theory]
    [InlineData(1799999940L)]
    [InlineData(1800000030L)]
    [InlineData(1800000060L)]
    public void CreatedWindowIsSymmetric(long created)
    {
        var input = "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + created;
        new AAuthVerifier { TimeProvider = Time }.ValidateInput(input, "sig");
    }

    [Fact]
    public async Task ConsumedAgentTokenOverTwentyFourHoursLogsWarning()
    {
        var httpKey = AAuthKey.Generate();
        var issuerKey = AAuthKey.Generate();
        var payload = new JsonObject
        {
            ["iss"] = "https://issuer.example",
            ["dwk"] = AgentTokenBuilder.AgentDwk,
            ["sub"] = "aauth:wire@issuer.example",
            ["jti"] = "long-lived-token",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.AddHours(25).ToUnixTimeSeconds(),
            ["cnf"] = new JsonObject { ["jwk"] = httpKey.ToPublicJwk() },
        };
        var header = new JsonObject
        {
            ["typ"] = AgentTokenBuilder.TokenType,
            ["kid"] = "issuer-key",
            ["alg"] = AAuthKey.Ed25519Algorithm,
        };
        var wire = "sig=jwt;jwt=\"" + await JwtAsync(header, payload, issuerKey) + "\"";
        var logger = new CapturingLoggerProvider();
        var services = new ServiceCollection()
            .AddLogging(builder => builder.AddProvider(logger))
            .BuildServiceProvider();
        using var http = new InProcessHttpClient(new DiscoveryHandler(issuerKey, httpKey),
            policy: new AAuthEgressPolicy(crossOriginJwks: [("https://issuer.example", "https://keys.example")]));
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(http), new MetadataClient(http),
            new TokenVerifier { EgressPolicy = TestEgress.Policy, TimeProvider = Time, ClockSkew = TimeSpan.Zero },
            services: services);

        _ = await resolver.ResolveAsync(SignatureKeyParser.ParseAny(wire));

        Assert.Contains(logger.Messages, message => message.Contains("24 hour", StringComparison.OrdinalIgnoreCase));
    }

    internal static async Task<string> JwtAsync(JsonObject header, JsonObject payload, IAAuthSigner key)
    {
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(await key.SignAsync(Encoding.ASCII.GetBytes(input)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TwoRealSignaturesBindTheCompleteKeyDictionary(bool sameKey)
    {
        IAAuthSigner first = AAuthKey.Generate();
        IAAuthSigner second = sameKey ? first : EcdsaAAuthKey.Generate();
        var carrier = SignatureKeyHeader.FormatHwk(first, "first") + ", " + SignatureKeyHeader.FormatHwk(second, "second");
        var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1800000000";
        var signatureBase = $"\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": {carrier}\n\"@signature-params\": {parameters}";
        var signatures = "first=:" + Convert.ToBase64String(await first.SignAsync(Encoding.ASCII.GetBytes(signatureBase)))
            + ":, second=:" + Convert.ToBase64String(await second.SignAsync(Encoding.ASCII.GetBytes(signatureBase))) + ":";
        var inputs = "first=" + parameters + ", second=" + parameters;
        var verifier = new AAuthVerifier { TimeProvider = Time };
        var firstIdentity = verifier.Verify("GET", "resource.example", "/wire", carrier, inputs, signatures, first, label: "first");
        var secondIdentity = verifier.Verify("GET", "resource.example", "/wire", carrier, inputs, signatures, second, label: "second");
        var store = new AAuth.Server.InMemoryJtiStore();
        Assert.True(await store.TryRecordRequestAsync(firstIdentity, DateTimeOffset.UtcNow.AddMinutes(1)));
        Assert.Equal(!sameKey, await store.TryRecordRequestAsync(secondIdentity, DateTimeOffset.UtcNow.AddMinutes(1)));
        Assert.Throws<AAuthVerificationException>(() => verifier.Verify("GET", "resource.example", "/wire",
            carrier.Replace("second=hwk", "second=unknown"), inputs, signatures, first, label: "first"));
    }

    [Theory]
    [InlineData("content-digest", "sha-256=:AQID:", "sha-256=:BAUG:")]
    [InlineData("authorization", "AAuth first", "AAuth second")]
    [InlineData("signature-key", "first", "second")]
    [InlineData("nonce", "first", "second")]
    public void ReplayIdentityDistinguishesCoveredValuesAndParameters(string component, string firstValue, string secondValue)
    {
        var key = EcdsaAAuthKey.Generate();
        Assert.NotEqual(Identity(firstValue), Identity(secondValue));

        string Identity(string value)
        {
            var carrier = SignatureKeyHeader.FormatHwk(key) + (component == "signature-key" ? ", " + value + "=unknown" : "");
            var extra = component is "nonce" or "signature-key" ? "" : " \"" + component + "\"";
            var parameters = "(\"@method\" \"@authority\" \"@path\" \"signature-key\"" + extra + ");created=1800000000"
                + (component == "nonce" ? ";nonce=\"" + value + "\"" : "");
            var signatureBase = $"\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /wire\n\"signature-key\": {carrier}\n"
                + (extra.Length > 0 ? $"\"{component}\": {value}\n" : "") + "\"@signature-params\": " + parameters;
            return new AAuthVerifier { TimeProvider = Time }.Verify("GET", "resource.example", "/wire", carrier,
                "sig=" + parameters, "sig=:" + Convert.ToBase64String(key.Sign(Encoding.ASCII.GetBytes(signatureBase))) + ":", key,
                authorization: component == "authorization" ? value : null,
                fields: new Dictionary<string, string> { [component] = value });
        }
    }

    private sealed class EventVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "self-jwt";
        public string TokenType => "test-event+jwt";
        public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken ct) =>
            ValueTask.FromResult<IAAuthKey?>(null);
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken ct) =>
            Task.FromResult(context.TokenVerifier.Verify(context.Jwt, context.IssuerKey, TokenType, "aauth-agent.json"));
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

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<string> Messages { get; } = [];
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
        public void Dispose() { }

        private sealed class CapturingLogger(List<string> messages) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
                Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (logLevel >= LogLevel.Warning)
                    messages.Add(formatter(state, exception));
            }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}