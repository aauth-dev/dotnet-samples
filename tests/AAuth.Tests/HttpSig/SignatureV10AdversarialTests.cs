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
    [InlineData("GuidedTour", "http://localhost:5400")]
    [InlineData("SampleApp", "http://localhost:5240")]
    public void SampleWorkerScenarioUsesHostOnlyAgentDomains(string assemblyName, string provider)
    {
        var type = System.Reflection.Assembly.Load(assemblyName).GetType("AAuth.Samples.FederatedWorkerScenario")!;
        var key = AAuthKey.Generate();
        using var scenario = (IDisposable)Activator.CreateInstance(type, key, "provider-key", provider,
            "http://localhost:5100", "http://localhost:5003")!;
        type.GetMethod("IssueParent")!.Invoke(scenario, null);
        type.GetMethod("IssueWorker")!.Invoke(scenario, null);
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var parent = verifier.VerifySelfIssuedAgentToken((string)type.GetProperty("ParentToken")!.GetValue(scenario)!, key);
        var worker = verifier.VerifySelfIssuedAgentToken((string)type.GetProperty("WorkerToken")!.GetValue(scenario)!, key);
        Assert.Equal("aauth:aria@localhost", (string?)parent.Payload["sub"]);
        Assert.Equal("aauth:aria+worker1@localhost", (string?)worker.Payload["sub"]);
        Assert.Equal((string?)parent.Payload["sub"], (string?)worker.Payload["parent_agent"]);
    }

    [Theory]
    [InlineData("kid", true)]
    [InlineData("alg", true)]
    [InlineData("aud", false)]
    [InlineData("cnf", false)]
    [InlineData("nested", false)]
    public async Task DuplicateRawMembersRejectBeforeDiscovery(string member, bool inHeader)
    {
        var key = AAuthKey.Generate();
        var original = TestTokens.Raw(key, AuthTokenBuilder.TokenType).Split('.');
        var header = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(original[0]);
        var payload = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(original[1]);
        var target = inHeader ? header : payload;
        var duplicate = member == "nested" ? "\"extension\":[{\"value\":1,\"value\":1}]"
            : System.Text.Json.JsonSerializer.Serialize(member) + ":" + JsonNode.Parse(target)![member]!.ToJsonString();
        target = target[..^1] + "," + duplicate + "}";
        if (inHeader) header = target;
        else payload = target;
        var input = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(header) + "."
            + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payload);
        var jwt = input + "." + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<TokenVerificationException>(() =>
            new TokenVerifier { Clock = () => Now }.Verify(jwt, key, AuthTokenBuilder.TokenType, AuthTokenBuilder.PersonDwk)).Code);
        var discovery = new DuplicateDiscoveryProbe();
        using var http = new InProcessHttpClient(discovery);
        using var metadata = new MetadataClient(http);
        using var jwks = new JwksClient(http);
        Assert.Equal(SignatureErrorCode.InvalidJwt, (await Assert.ThrowsAsync<TokenVerificationException>(() =>
            new TokenVerifier { Clock = () => Now }.VerifyWithJwksAsync(jwt, metadata, jwks,
                AuthTokenBuilder.TokenType, AuthTokenBuilder.PersonDwk, "https://resource.example"))).Code);
        foreach (var scheme in new[] { "jwt", "jkt-jwt", "self-jwt" })
        {
            Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<AAuthVerificationException>(() =>
                SignatureKeyParser.ParseAny($"sig={scheme};jwt=\"{jwt}\"")).Code);
            var context = Signed(key, $"sig={scheme};jwt=\"{jwt}\"");
            using var activity = new System.Diagnostics.Activity("duplicate-jwt").Start();
            await Middleware(http, AAuthVerificationOptions.Generic(() => Now)).InvokeAsync(context);
            Assert.Equal(401, context.Response.StatusCode);
            Assert.Equal("error=invalid_jwt", context.Response.Headers["Signature-Error"].ToString());
            Assert.Null(context.Features.Get<AAuthVerificationResult>());
            Assert.Null(context.Features.Get<AAuthVerifiedAssertion>());
            Assert.False(context.Items.ContainsKey(AAuthVerificationMiddleware.ContextItemKey));
            Assert.False(context.User.Identity?.IsAuthenticated ?? false);
            Assert.Empty(activity.Events);
            Assert.Empty(activity.Tags);
        }
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<AAuthVerificationException>(() =>
            NamingTokenVerifier.Verify(jwt, Now, TimeSpan.Zero)).Code);
        Assert.Equal(0, discovery.Calls);
    }

    private sealed class DuplicateDiscoveryProbe : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Theory]
    [InlineData("kid", true)]
    [InlineData("alg", true)]
    [InlineData("aud", false)]
    [InlineData("cnf", false)]
    [InlineData("nested-jwk", false)]
    public async Task ValidNamingJwtRejectsRawDuplicateMembers(string member, bool inHeader)
    {
        var durable = EcdsaAAuthKey.Generate();
        var confirmation = AAuthKey.Generate();
        var header = new JsonObject { ["alg"] = durable.Algorithm, ["typ"] = "jkt-s256+jwt", ["kid"] = "durable", ["jwk"] = durable.ToPublicJwk() }.ToJsonString();
        var payload = new JsonObject
        {
            ["iss"] = "urn:jkt:sha-256:" + durable.ComputeJwkThumbprint(), ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(), ["aud"] = "https://resource.example",
            ["cnf"] = new JsonObject { ["jwk"] = confirmation.ToPublicJwk() },
        }.ToJsonString();
        string Sign()
        {
            var input = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(header) + "."
                + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payload);
            return input + "." + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(durable.Sign(Encoding.ASCII.GetBytes(input)));
        }
        Assert.NotNull(NamingTokenVerifier.Verify(Sign(), Now, TimeSpan.Zero));
        if (member == "nested-jwk")
        {
            var jwk = confirmation.ToPublicJwk().ToJsonString();
            payload = payload.Replace(jwk, jwk[..^1] + ",\"alg\":\"Ed25519\"}", StringComparison.Ordinal);
        }
        else
        {
            var target = inHeader ? header : payload;
            target = target[..^1] + "," + System.Text.Json.JsonSerializer.Serialize(member) + ":" + JsonNode.Parse(target)![member]!.ToJsonString() + "}";
            if (inHeader) header = target;
            else payload = target;
        }
        var jwt = Sign();
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<AAuthVerificationException>(() => NamingTokenVerifier.Verify(jwt, Now, TimeSpan.Zero)).Code);
        var discovery = new DuplicateDiscoveryProbe();
        using var http = new InProcessHttpClient(discovery);
        var context = Signed(confirmation, SignatureKeyHeader.FormatJktJwt(jwt));
        await Middleware(http, AAuthVerificationOptions.Generic(() => Now)).InvokeAsync(context);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("error=invalid_jwt", context.Response.Headers["Signature-Error"].ToString());
        Assert.Null(context.Features.Get<AAuthVerifiedAssertion>());
        Assert.Null(context.Features.Get<AAuthVerificationResult>());
        Assert.False(context.Items.ContainsKey(AAuthVerificationMiddleware.ContextItemKey));
        Assert.Equal(0, discovery.Calls);
    }

    public static IEnumerable<object[]> InvalidCarrierClaims => TestTokens.InvalidRequiredClaims
        .Where(test => (string)test[0] != ResourceTokenBuilder.TokenType);

    [Theory]
    [InlineData("bad/path")]
    [InlineData("ap.example:443")]
    [InlineData("ap.example?query")]
    [InlineData("ap.example#fragment")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("b\u00fccher.example")]
    [InlineData("localhost")]
    public async Task InvalidActorDomainsRejectAtEveryDepth(string domain)
    {
        var key = AAuthKey.Generate();
        var invalid = new JsonObject { ["agent"] = "aauth:actor@" + domain };
        foreach (var act in new[] { invalid, new JsonObject { ["agent"] = "aauth:other@different.example", ["act"] = invalid.DeepClone() } })
        {
            Assert.False(ActChainBuilder.ValidateChain(act));
            Assert.Throws<ArgumentException>(() => ActChainBuilder.BuildNestedAct("aauth:next@another.example", act));
            var payload = new JsonObject { ["act"] = act.DeepClone() };
            Assert.Throws<InvalidOperationException>(() => ActChainReader.GetDelegationChain(payload));
            Assert.Throws<InvalidOperationException>(() => ActChainReader.GetImmediateActor(payload));
            var jwt = TestTokens.Raw(key, AuthTokenBuilder.TokenType, (_, body) => body["act"] = act.DeepClone());
            Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<TokenVerificationException>(() =>
                new TokenVerifier { Clock = () => Now }.VerifyAuthToken(jwt, key, "https://resource.example", key, "aauth:wire@issuer.example")).Code);
            var context = Signed(key, SignatureKeyHeader.FormatJwt(jwt));
            await Middleware(null).InvokeAsync(context);
            Assert.Equal(401, context.Response.StatusCode);
            Assert.Equal("error=invalid_jwt", context.Response.Headers["Signature-Error"].ToString());
            Assert.Null(context.Features.Get<AAuthVerifiedAssertion>());
        }
    }

    [Theory]
    [InlineData("xn--bcher-kva.example", false)]
    [InlineData("another.example", false)]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    public void ActorDomainsUseExplicitPolicyWithoutSameProviderRequirement(string domain, bool development)
    {
        var policy = development ? AAuthEgressPolicy.ForDevelopmentLoopback("http://" + domain + ":5010") : AAuthEgressPolicy.Production;
        var actor = "aauth:actor@" + domain;
        var chain = ActChainBuilder.BuildNestedAct(actor, policy: policy);
        var act = ActChainBuilder.BuildNestedAct("aauth:next@different.example", chain, policy);
        var payload = new JsonObject { ["act"] = act.DeepClone() };
        Assert.True(ActChainBuilder.ValidateChain(act, policy: policy));
        Assert.Equal(actor, ActChainReader.GetOriginalActor(payload, policy: policy));
        Assert.Equal(2, ActChainReader.GetChainDepth(payload, policy: policy));
        Assert.Equal(2, ActChainReader.GetDelegationChain(payload, policy: policy).Count);
        Assert.Equal("aauth:next@different.example", ActChainReader.GetImmediateActor(payload, policy));
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, AuthTokenBuilder.TokenType, (_, body) => body["act"] = act);
        Assert.NotNull(new TokenVerifier { Clock = () => Now, EgressPolicy = policy }
            .VerifyAuthToken(jwt, key, "https://resource.example", key, "aauth:wire@issuer.example"));
        Assert.True(AuthTokenResponseValidator.ActChainsMatch(act, (JsonObject)act.DeepClone(), policy));
        if (development)
        {
            Assert.False(ActChainBuilder.ValidateChain(act));
            Assert.Throws<ArgumentException>(() => ActChainBuilder.BuildNestedAct(actor + ":5010", policy: policy));
            var httpsPolicy = AAuthEgressPolicy.ForDevelopmentLoopback("https://" + domain + ":5010");
            Assert.Throws<ArgumentException>(() => ActChainBuilder.BuildNestedAct(actor + ":5010", policy: httpsPolicy));
        }
    }

    [Theory]
    [InlineData("aa-agent+jwt", "ps", "null")]
    [InlineData("aa-agent+jwt", "ps", "123")]
    [InlineData("aa-agent+jwt", "ps", "\"http://ps.example\"")]
    [InlineData("aa-agent+jwt", "ps", "\"https://ps.example/path\"")]
    [InlineData("aa-agent+jwt", "ps", "\"https://PS.example\"")]
    [InlineData("aa-agent+jwt", "ps", "\"http://localhost:5010\"")]
    [InlineData("aa-agent+jwt", "parent_agent", "null")]
    [InlineData("aa-agent+jwt", "parent_agent", "123")]
    [InlineData("aa-agent+jwt", "parent_agent", "\"parent\"")]
    [InlineData("aa-agent+jwt", "parent_agent", "\"aauth:parent@bad/path\"")]
    [InlineData("aa-agent+jwt", "sub", "\"aauth:wire@bad/path\"")]
    [InlineData("aa-agent+jwt", "sub", "\"aauth:wire@other.example\"")]
    [InlineData("aa-auth+jwt", "aud", "123")]
    [InlineData("aa-auth+jwt", "aud", "[]")]
    [InlineData("aa-auth+jwt", "sub", "null")]
    [InlineData("aa-auth+jwt", "sub", "\"\"")]
    [InlineData("aa-auth+jwt", "agent", "\"aauth:wire@bad/path\"")]
    [InlineData("aa-auth+jwt", "act", "{\"agent\":123}")]
    [InlineData("aa-auth+jwt", "mission", "{\"approver\":123,\"s256\":\"bad\"}")]
    [InlineData("aa-auth+jwt", "iat", "-9223372036854775808")]
    [InlineData("aa-auth+jwt", "iat", "9223372036854775807")]
    [InlineData("aa-auth+jwt", "iat", "1800000000.5")]
    [InlineData("aa-auth+jwt", "iat", "\"1800000000\"")]
    [InlineData("aa-auth+jwt", "exp", "1800003601")]
    [InlineData("aa-agent+jwt", "exp", "9223372036854775807")]
    [InlineData("aa-agent+jwt", "exp", "-9223372036854775808")]
    public async Task RawMalformedValuesHaveTypedErrorsWithoutTrustedContext(string type, string claim, string json)
    {
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, type, (_, payload) => payload[claim] = JsonNode.Parse(json));
        var verifier = new TokenVerifier { Clock = () => Now };
        Assert.Equal(SignatureErrorCode.InvalidJwt, Assert.Throws<TokenVerificationException>(() => verifier.Verify(jwt, key, type,
            type == AgentTokenBuilder.TokenType ? AgentTokenBuilder.AgentDwk : AuthTokenBuilder.PersonDwk)).Code);
        var context = Signed(key, SignatureKeyHeader.FormatJwt(jwt));
        using var activity = new System.Diagnostics.Activity("malformed-jwt").Start();
        await Middleware(null).InvokeAsync(context);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("error=invalid_jwt", context.Response.Headers["Signature-Error"].ToString());
        Assert.Null(context.Features.Get<AAuthVerificationResult>());
        Assert.Null(context.Features.Get<AAuthVerifiedAssertion>());
        Assert.Empty(activity.Events);
        Assert.Empty(activity.Tags);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RegisteredCustomTypeWithoutOptionalIatOrJtiInvokesItsPolicy(bool allow)
    {
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, AgentTokenBuilder.TokenType, (header, payload) =>
        {
            header["typ"] = "custom+jwt";
            payload.Remove("iat");
            payload.Remove("jti");
        });
        var custom = new CustomVerifier(allow);
        using var http = new InProcessHttpClient(new Discovery(key, ""));
        var context = Signed(key, SignatureKeyHeader.FormatJwt(jwt));
        var middleware = new AAuthVerificationMiddleware(_ => Task.CompletedTask, new AAuthVerifier { Clock = () => Now },
            new DefaultSignatureKeyResolver(tokenVerifiers: [custom]), new MetadataClient(http), new JwksClient(http),
            new() { Clock = () => Now });
        await middleware.InvokeAsync(context);
        Assert.Equal(1, custom.Calls);
        Assert.Equal(allow ? 200 : 401, context.Response.StatusCode);
        Assert.Equal(allow, context.Features.Get<AAuthVerifiedAssertion>() is not null);
    }

    private sealed class CustomVerifier(bool allow) : ISignatureTokenVerifier
    {
        public string Scheme => "jwt";
        public string TokenType => "custom+jwt";
        public int Calls { get; private set; }
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(string jwt, IAAuthKey key, TokenVerifier verifier, CancellationToken ct)
        {
            Calls++;
            var verified = verifier.Verify(jwt, key, TokenType, AgentTokenBuilder.AgentDwk);
            if (!allow) throw new TokenVerificationException("Custom policy denied.");
            return Task.FromResult(verified);
        }
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    public void LoopbackAgentClaimsRequireExplicitDevelopmentPolicy(string host)
    {
        var key = AAuthKey.Generate();
        var issuer = "http://" + host + ":5010";
        var jwt = TestTokens.Raw(key, AgentTokenBuilder.TokenType, (_, payload) =>
        {
            payload["iss"] = issuer;
            payload["sub"] = "aauth:wire@" + host;
            payload["parent_agent"] = "aauth:parent@" + host;
            payload["ps"] = issuer;
        });
        Assert.Throws<TokenVerificationException>(() => new TokenVerifier { Clock = () => Now }
            .VerifySelfIssuedAgentToken(jwt, key));
        Assert.NotNull(new TokenVerifier { Clock = () => Now, EgressPolicy = AAuthEgressPolicy.ForDevelopmentLoopback(issuer) }
            .VerifySelfIssuedAgentToken(jwt, key));
    }

    [Theory]
    [MemberData(nameof(InvalidCarrierClaims))]
    public async Task RawMandatoryClaimsNeverCreateTrustedContext(string type, string claim, string mutation)
    {
        var key = AAuthKey.Generate();
        var jwt = TestTokens.Raw(key, type, (header, payload) => TestTokens.Mutate(header, payload, claim, mutation));
        var context = Signed(key, SignatureKeyHeader.FormatJwt(jwt));
        await Middleware(null, new() { Clock = () => Now, ResourceIdentifier = "https://resource.example" }).InvokeAsync(context);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("error=invalid_jwt", context.Response.Headers["Signature-Error"].ToString());
        Assert.Null(context.Features.Get<AAuthVerificationResult>());
        Assert.Null(context.Features.Get<AAuthVerifiedAssertion>());
        Assert.False(context.Items.ContainsKey(AAuthVerificationMiddleware.ContextItemKey));
        Assert.False(context.User.Identity?.IsAuthenticated ?? false);
        Assert.False(context.Response.Headers.ContainsKey("AAuth-Error"));
    }

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
        var payload = new JsonObject { ["iss"] = "https://issuer.example", ["dwk"] = "aauth-agent.json", ["sub"] = "aauth:wire@issuer.example", ["jti"] = "token-id",
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

    [Fact]
    public async Task UnexpectedResolverDefectsAreNotAuthenticationFailures()
    {
        var key = AAuthKey.Generate();
        var context = Signed(key, SignatureKeyHeader.FormatHwk(key));
        var middleware = new AAuthVerificationMiddleware(_ => Task.CompletedTask,
            new AAuthVerifier { Clock = () => Now }, new BrokenResolver(), null, null, AAuthVerificationOptions.Generic(() => Now));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));
        Assert.Equal("Programming defect", error.Message);
        Assert.False(context.Response.Headers.ContainsKey("Signature-Error"));
    }

    private sealed class BrokenResolver : ISignatureKeyResolver
    {
        public Task<SignatureKeyResolution> ResolveAsync(SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct = default) =>
            throw new InvalidOperationException("Programming defect");
    }

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