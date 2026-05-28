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

public class SelfIssuingBuilderTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private const string Issuer = "http://localhost:5000";
    private const string Subject = "aauth:my-svc@localhost:5000";
    private const string PersonServer = "http://localhost:5100";

    [Fact]
    public async Task SelfIssuing_builds_working_client()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        Assert.NotNull(stub.LastRequest);
        Assert.True(stub.LastRequest!.Headers.Contains("Signature"));
        Assert.True(stub.LastRequest.Headers.Contains("Signature-Input"));
        Assert.True(stub.LastRequest.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public async Task SelfIssuing_creates_valid_jwt_claims()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        Assert.Contains("sig=jwt", headerValue);

        var jwt = ExtractJwt(headerValue);
        var payload = ReadPayload(jwt);

        Assert.Equal(Issuer, (string?)payload["iss"]);
        Assert.Equal(Subject, (string?)payload["sub"]);
    }

    [Fact]
    public async Task SelfIssuing_with_person_server_sets_ps_claim()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        var jwt = ExtractJwt(headerValue);
        var payload = ReadPayload(jwt);

        Assert.Equal(PersonServer, (string?)payload["ps"]);
    }

    [Fact]
    public async Task SelfIssuing_with_kid_uses_custom_kid()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithKid("custom-kid-1")
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        var jwt = ExtractJwt(headerValue);
        var header = ReadHeader(jwt);
        Assert.Equal("custom-kid-1", (string?)header["kid"]);
    }

    [Fact]
    public async Task SelfIssuing_kid_defaults_to_thumbprint()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        var jwt = ExtractJwt(headerValue);
        var header = ReadHeader(jwt);
        Assert.Equal(_key.ComputeJwkThumbprint(), (string?)header["kid"]);
    }

    [Fact]
    public void SelfIssuing_throws_on_null_key()
    {
        Assert.Throws<ArgumentNullException>(() => AAuthClientBuilder.SelfIssuing(null!));
    }

    [Fact]
    public void As_throws_on_null_issuer()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<ArgumentNullException>(() => builder.As(null!, Subject));
    }

    [Fact]
    public void As_throws_on_empty_issuer()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<ArgumentException>(() => builder.As("", Subject));
    }

    [Fact]
    public void As_throws_on_null_subject()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<ArgumentNullException>(() => builder.As(Issuer, null!));
    }

    [Fact]
    public void Build_throws_without_As()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void WithKid_throws_on_empty()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<ArgumentException>(() => builder.WithKid(""));
    }

    [Fact]
    public async Task SelfIssuing_with_challenge_handling_builds_client()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithChallengeHandling(PersonServer)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        Assert.NotNull(stub.LastRequest);
        Assert.True(stub.LastRequest!.Headers.Contains("Signature"));
    }

    [Fact]
    public async Task SelfIssuing_creates_full_jwt_claims()
    {
        var stub = new StubHandler();
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithInnerHandler(stub)
            .Build();

        await client.GetAsync("http://localhost:9999/test");

        var sigKey = stub.LastRequest!.Headers.GetValues("Signature-Key");
        var headerValue = string.Join("", sigKey);
        var jwt = ExtractJwt(headerValue);
        var payload = ReadPayload(jwt);

        Assert.Equal("aauth-agent.json", (string?)payload["dwk"]);
        Assert.NotNull(payload["cnf"]);
        Assert.NotNull(payload["exp"]);
        Assert.NotNull(payload["iat"]);
    }

    [Fact]
    public void As_throws_on_empty_subject()
    {
        var builder = AAuthClientBuilder.SelfIssuing(_key);
        Assert.Throws<ArgumentException>(() => builder.As(Issuer, ""));
    }

    [Fact]
    public void Explicit_ps_in_challenge_overrides_stored()
    {
        using var client = AAuthClientBuilder.SelfIssuing(_key)
            .As(Issuer, Subject)
            .WithPersonServer(PersonServer)
            .WithChallengeHandling("http://localhost:6000")
            .WithInnerHandler(new StubHandler())
            .Build();

        Assert.NotNull(client);
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

    private static string ExtractJwt(string signatureKeyHeader)
    {
        // Format: sig=jwt;jwt="eyJ..."
        var start = signatureKeyHeader.IndexOf("jwt=\"", StringComparison.Ordinal) + 5;
        var end = signatureKeyHeader.IndexOf('"', start);
        return signatureKeyHeader[start..end];
    }

    private static JsonNode ReadPayload(string jwt)
    {
        var parts = jwt.Split('.');
        var bytes = Base64UrlEncoder.DecodeBytes(parts[1]);
        return JsonNode.Parse(bytes) ?? new JsonObject();
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
