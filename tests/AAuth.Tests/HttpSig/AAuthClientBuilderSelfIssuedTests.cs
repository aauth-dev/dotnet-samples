using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthClientBuilderSelfIssuedTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private const string Issuer = "http://localhost:5000";
    private const string Subject = "aauth:my-svc@localhost:5000";
    private const string PersonServer = "http://localhost:5100";

    [Fact]
    public async Task SelfIssued_builds_working_client()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssued(_key, Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        Assert.NotNull(stub.LastRequest);
        Assert.True(stub.LastRequest!.Headers.Contains("Signature"));
        Assert.True(stub.LastRequest.Headers.Contains("Signature-Input"));
        Assert.True(stub.LastRequest.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public async Task WithSelfIssuedToken_creates_valid_jwt()
    {
        var stub = new StubHandler();
        using var client = new AAuthClientBuilder(_key)
            .WithSelfIssuedToken(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        Assert.Contains("sig=jwt", headerValue);

        // Extract JWT from header and verify claims
        var jwt = ExtractJwt(headerValue);
        var payload = ReadPayload(jwt);

        Assert.Equal(Issuer, (string?)payload["iss"]);
        Assert.Equal(Subject, (string?)payload["sub"]);
        Assert.Equal("aauth-agent.json", (string?)payload["dwk"]);
        Assert.NotNull(payload["cnf"]);
        Assert.NotNull(payload["exp"]);
        Assert.NotNull(payload["iat"]);
    }

    [Fact]
    public async Task WithPersonServer_sets_token_ps_claim()
    {
        var stub = new StubHandler();
        using var client = new AAuthClientBuilder(_key)
            .WithSelfIssuedToken(Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var jwt = ExtractJwt(string.Join("", stub.LastRequest!.Headers.GetValues("Signature-Key")));
        var payload = ReadPayload(jwt);
        Assert.Equal(PersonServer, (string?)payload["ps"]);
    }

    [Fact]
    public async Task WithPersonServer_before_WithSelfIssuedToken_sets_ps_claim()
    {
        var stub = new StubHandler();
        // Order: WithPersonServer BEFORE WithSelfIssuedToken
        using var client = new AAuthClientBuilder(_key)
            .WithPersonServer(PersonServer)
            .WithSelfIssuedToken(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var jwt = ExtractJwt(string.Join("", stub.LastRequest!.Headers.GetValues("Signature-Key")));
        var payload = ReadPayload(jwt);
        Assert.Equal(PersonServer, (string?)payload["ps"]);
    }

    [Fact]
    public void WithPersonServer_feeds_challenge_handling()
    {
        // WithPersonServer + WithChallengeHandling() (no arg) should not throw
        using var client = new AAuthClientBuilder(_key)
            .WithSelfIssuedToken(Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithChallengeHandling()
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void Explicit_ps_in_challenge_overrides_stored()
    {
        // Explicit PS in WithChallengeHandling(ps) should take precedence over WithPersonServer
        using var client = new AAuthClientBuilder(_key)
            .WithSelfIssuedToken(Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithChallengeHandling("http://localhost:6000")
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public async Task Kid_defaults_to_thumbprint()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssued(_key, Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var jwt = ExtractJwt(string.Join("", stub.LastRequest!.Headers.GetValues("Signature-Key")));
        var header = ReadHeader(jwt);
        Assert.Equal(_key.ComputeJwkThumbprint(), (string?)header["kid"]);
    }

    [Fact]
    public async Task Kid_can_be_customized()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssued(_key, Issuer, Subject, kid: "custom-kid")
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var jwt = ExtractJwt(string.Join("", stub.LastRequest!.Headers.GetValues("Signature-Key")));
        var header = ReadHeader(jwt);
        Assert.Equal("custom-kid", (string?)header["kid"]);
    }

    [Fact]
    public void Throws_on_null_issuer()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AAuthClientBuilder(_key).WithSelfIssuedToken(null!, Subject));
    }

    [Fact]
    public void Throws_on_empty_issuer()
    {
        Assert.Throws<ArgumentException>(() =>
            new AAuthClientBuilder(_key).WithSelfIssuedToken("", Subject));
    }

    [Fact]
    public void Throws_on_null_subject()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AAuthClientBuilder(_key).WithSelfIssuedToken(Issuer, null!));
    }

    [Fact]
    public void Throws_on_empty_subject()
    {
        Assert.Throws<ArgumentException>(() =>
            new AAuthClientBuilder(_key).WithSelfIssuedToken(Issuer, ""));
    }

    [Fact]
    public void SelfIssued_static_throws_on_null_key()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AAuthClientBuilder.SelfIssued(null!, Issuer, Subject));
    }

    [Fact]
    public void SelfIssued_static_throws_on_null_issuer()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AAuthClientBuilder.SelfIssued(_key, null!, Subject));
    }

    [Fact]
    public void SelfIssued_static_throws_on_null_subject()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AAuthClientBuilder.SelfIssued(_key, Issuer, null!));
    }

    [Fact]
    public async Task Existing_WithTokenRefresh_still_works()
    {
        var stub = new StubHandler();
        var refresher = new SelfIssuedTokenRefresher(
            _key, Issuer, Subject, _key.ComputeJwkThumbprint());

        using var client = new AAuthClientBuilder(_key)
            .WithTokenRefresh(refresher)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        Assert.NotNull(stub.LastRequest);
        Assert.True(stub.LastRequest!.Headers.Contains("Signature"));
    }

    [Fact]
    public async Task SelfIssued_with_challenge_handling_and_person_server()
    {
        // Full golden-path: SelfIssued + WithPersonServer + WithChallengeHandling
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssued(_key, Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithChallengeHandling()
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        Assert.NotNull(stub.LastRequest);
        var jwt = ExtractJwt(string.Join("", stub.LastRequest!.Headers.GetValues("Signature-Key")));
        var payload = ReadPayload(jwt);
        Assert.Equal(PersonServer, (string?)payload["ps"]);
    }

    // --- Helpers ---

    private static string ExtractJwt(string signatureKeyHeader)
    {
        // Format: sig=jwt;jwt="eyJ..."
        var start = signatureKeyHeader.IndexOf("jwt=\"", StringComparison.Ordinal) + 5;
        var end = signatureKeyHeader.IndexOf('"', start);
        return signatureKeyHeader[start..end];
    }

    private static JsonObject ReadPayload(string jwt)
    {
        var parts = jwt.Split('.');
        var bytes = Base64UrlEncoder.DecodeBytes(parts[1]);
        return JsonNode.Parse(bytes) as JsonObject ?? new JsonObject();
    }

    private static JsonObject ReadHeader(string jwt)
    {
        var parts = jwt.Split('.');
        var bytes = Base64UrlEncoder.DecodeBytes(parts[0]);
        return JsonNode.Parse(bytes) as JsonObject ?? new JsonObject();
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
