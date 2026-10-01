using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Discovery;

public class IssuerDiscoverySecurityTests
{
    private const string Issuer = "https://issuer.example";
    private const string Audience = "https://resource.example";
    private const string Agent = "aauth:agent@example";

    [Theory]
    [InlineData("generic")]
    [InlineData("auth")]
    public async Task SameKidRefreshReportsUnknownKeyWhenIssuerRemovesIt(string path)
    {
        using var scenario = new Scenario();
        Assert.True(await scenario.Verify(path));
        scenario.Time.SetUtcNow(scenario.Start.AddSeconds(61));
        scenario.Handler.Key = AAuthKey.Generate();
        scenario.Handler.PublishKey = false;
        var exception = await Assert.ThrowsAsync<TokenVerificationException>(() => scenario.Verify(path));
        Assert.Equal(AAuth.Errors.SignatureErrorCode.UnknownKey, exception.Code);
        Assert.Equal(2, scenario.Handler.KeyCalls);
    }

    [Theory]
    [InlineData("generic")]
    [InlineData("auth")]
    [InlineData("upstream")]
    [InlineData("delivery")]
    [InlineData("jwt")]
    [InlineData("jwks_uri")]
    [InlineData("self-jwt")]
    public async Task MetadataUrlSwapCannotResetIssuerFloor(string path)
    {
        using var scenario = new Scenario();
        Assert.True(await scenario.Verify(path));
        scenario.Time.SetUtcNow(scenario.Start.AddSeconds(299));
        scenario.Handler.Kid = "second";
        Assert.True(await scenario.Verify(path));
        Assert.Equal(2, scenario.Handler.KeyCalls);
        scenario.Time.SetUtcNow(scenario.Start.AddSeconds(301));
        scenario.Handler.Location = "keys-b";
        scenario.Handler.Kid = "third";
        var accepted = false;
        try { accepted = await scenario.Verify(path); }
        catch (HttpRequestException) { }
        catch (TokenVerificationException) { }
        Assert.False(accepted);
        Assert.Equal(2, scenario.Handler.KeyCalls);
        Assert.Equal(2, scenario.Handler.MetadataCalls);
        scenario.Time.SetUtcNow(scenario.Start.AddSeconds(359));
        Assert.True(await scenario.Verify(path));
        Assert.Equal(3, scenario.Handler.KeyCalls);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(61, true)]
    public async Task UpstreamSameKidRotationUsesSharedRefresh(int elapsedSeconds, bool accepted)
    {
        using var scenario = new Scenario();
        Assert.True(await scenario.Verify("upstream"));
        scenario.Handler.Key = AAuthKey.Generate();
        scenario.Time.SetUtcNow(scenario.Start.AddSeconds(elapsedSeconds));
        Assert.Equal(accepted, await scenario.Verify("upstream"));
        Assert.Equal(accepted ? 2 : 1, scenario.Handler.KeyCalls);
    }

    private sealed class Scenario : IDisposable
    {
        public DateTimeOffset Start { get; } = DateTimeOffset.UtcNow;
        public FakeTimeProvider Time { get; }
        public Handler Handler { get; } = new();
        private readonly AAuthKey _agent = AAuthKey.Generate();
        private readonly HttpClient _http;
        private readonly MetadataClient _metadata;
        private readonly JwksClient _jwks;
        private readonly TokenVerifier _verifier;

        public Scenario()
        {
            Time = new FakeTimeProvider(Start);
            _http = AAuthHttpTransport.AttachPolicy(new HttpClient(Handler), AAuthEgressPolicy.Production,
                AAuthTransportContract.InProcessOnly);
            _metadata = new(_http, timeProvider: Time);
            _jwks = new(_http, timeProvider: Time);
            _verifier = new() { TimeProvider = Time };
        }

        public async Task<bool> Verify(string path)
        {
            var jwt = await new AuthTokenBuilder
            {
                Issuer = Issuer, Audience = Audience, PersonServer = Issuer, Subject = "person", Scope = "read",
                AgentConfirmationKey = _agent, AgentTokenExpiresAt = Start.AddHours(1),
                Key = Handler.Key, KeyId = Handler.Kid, Dwk = AuthTokenBuilder.AccessDwk,
            }.BuildAsync();
            switch (path)
            {
                case "generic":
                    await _verifier.VerifyWithJwksAsync(jwt, _metadata, _jwks, AuthTokenBuilder.TokenType,
                        AuthTokenBuilder.AccessDwk, Audience);
                    return true;
                case "auth":
                    await _verifier.VerifyAuthTokenWithJwksAsync(jwt, _metadata, _jwks, Audience, _agent);
                    return true;
                case "upstream":
                    return (await new UpstreamTokenValidator(_metadata, _jwks, _verifier)
                        .ValidateAsync(jwt, Audience, Issuer, (issuer, _) => ValueTask.FromResult(issuer == Issuer))).IsValid;
                case "delivery":
                    return (await new AuthTokenResponseValidator(_metadata, _jwks, _verifier)
                        .ValidateAsync(jwt, Issuer, Audience, "person", Issuer, _agent, Start.AddHours(2))).IsValid;
                default:
                    var segments = jwt.Split('.');
                    if (path == "self-jwt")
                    {
                        var header = TokenVerifier.DecodeJsonSegment(segments[0], "header");
                        header["typ"] = "cache-test+jwt";
                        var payload = TokenVerifier.DecodeJsonSegment(segments[1], "payload");
                        payload.Remove("cnf");
                        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
                        jwt = input + "." + Base64UrlEncoder.Encode(Handler.Key.Sign(Encoding.ASCII.GetBytes(input)));
                        segments = jwt.Split('.');
                    }
                    var info = new SignatureKeyParser.ParsedSignatureKeyInfo
                    {
                        Scheme = path, Identifier = Issuer, Dwk = AuthTokenBuilder.AccessDwk,
                        Kid = Handler.Kid, Jwt = jwt,
                        Header = TokenVerifier.DecodeJsonSegment(segments[0], "header"),
                        Payload = TokenVerifier.DecodeJsonSegment(segments[1], "payload"),
                    };
                    await new DefaultSignatureKeyResolver(_jwks, _metadata, _verifier, [new SelfVerifier()]).ResolveAsync(info);
                    return true;
            }
        }

        public void Dispose() => _http.Dispose();
    }

    private sealed class SelfVerifier : ISignatureTokenVerifier
    {
        public string Scheme => "self-jwt";
        public string TokenType => "cache-test+jwt";
        public ValueTask<IAAuthKey?> ResolveIssuerKeyAsync(SignatureTokenIssuerKeyContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IAAuthKey?>(null);
        public Task<TokenVerifier.VerifiedToken> VerifyAsync(SignatureTokenVerificationContext context, CancellationToken cancellationToken) =>
            Task.FromResult(context.TokenVerifier.Verify(context.Jwt, context.IssuerKey, TokenType, AuthTokenBuilder.AccessDwk));
    }

    private sealed class Handler : HttpMessageHandler
    {
        public AAuthKey Key { get; set; } = AAuthKey.Generate();
        public string Kid { get; set; } = "first";
        public string Location { get; set; } = "keys-a";
        public bool PublishKey { get; set; } = true;
        public int KeyCalls { get; private set; }
        public int MetadataCalls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            JsonObject body;
            if (request.RequestUri!.AbsolutePath.Contains(".well-known"))
            {
                MetadataCalls++;
                body = new() { ["issuer"] = Issuer, ["jwks_uri"] = Issuer + "/" + Location };
            }
            else
            {
                KeyCalls++;
                var jwk = Key.ToPublicJwk();
                jwk["kid"] = Kid;
                body = new() { ["keys"] = PublishKey ? new JsonArray(jwk) : new JsonArray() };
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) });
        }
    }
}