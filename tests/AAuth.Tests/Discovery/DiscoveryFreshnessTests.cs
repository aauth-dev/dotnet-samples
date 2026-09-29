using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AAuth.Tests.Discovery;

public class DiscoveryFreshnessTests
{
    [Theory]
    [InlineData("max-age=60", 3600, 0, 0, 3600, 61, 2)]
    [InlineData("max-age=3600", 1, 0, 0, 1, 61, 1)]
    [InlineData(null, 60, 0, 0, 3600, 61, 2)]
    [InlineData(null, 3600, 0, 0, 1, 61, 1)]
    [InlineData("max-age=120", null, 90, 0, 3600, 61, 2)]
    [InlineData("max-age=120", null, 0, 90, 3600, 61, 2)]
    [InlineData("max-age=120", null, 50, 50, 3600, 61, 1)]
    [InlineData("max-age=999999", null, 0, 0, 3600, 86400, 2)]
    [InlineData("no-cache, max-age=3600", null, 0, 0, 3600, 61, 2)]
    [InlineData("no-store, max-age=3600", null, 0, 0, 3600, 61, 2)]
    [InlineData("max-age=0", null, 0, 0, 3600, 61, 2)]
    [InlineData(null, null, 0, 0, 1, 61, 2)]
    [InlineData("s-maxage=1, max-age=3600", null, 0, 0, 1, 61, 1)]
    public async Task HttpHeadersDetermineBoundedFreshness(string? cacheControl, int? expiresSeconds,
        int ageSeconds, int dateAgeSeconds, int fallbackSeconds, int elapsedSeconds, int expectedCalls)
    {
        foreach (var metadataMode in new[] { false, true })
        {
            var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
            var handler = new Handler(time, cacheControl, expiresSeconds, ageSeconds, dateAgeSeconds);
            using var http = AAuthHttpTransport.AttachPolicy(new HttpClient(handler), AAuthEgressPolicy.Production,
                AAuthTransportContract.InProcessOnly);
            var jwks = new JwksClient(http, cacheTtl: TimeSpan.FromSeconds(fallbackSeconds), timeProvider: time);
            var metadata = new MetadataClient(http, cacheTtl: TimeSpan.FromSeconds(fallbackSeconds), timeProvider: time);
            async Task Fetch()
            {
                if (metadataMode) await metadata.FetchAsync(new Uri("https://issuer.example/.well-known/aauth-agent.json"));
                else Assert.NotNull(await jwks.ResolveKeyAsync(new Uri("https://issuer.example/jwks"), "key"));
            }
            await Fetch();
            time.Advance(TimeSpan.FromSeconds(elapsedSeconds));
            await Fetch();
            Assert.Equal(expectedCalls, handler.Calls);
        }
    }

    [Theory]
    [InlineData("no-cache")]
    [InlineData("no-store")]
    [InlineData("max-age=0, must-revalidate")]
    public async Task RevalidationDirectivesNeverServeStaleOrBypassFloor(string cacheControl)
    {
        foreach (var metadataMode in new[] { false, true })
        {
            var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
            var handler = new Handler(time, cacheControl);
            using var http = AAuthHttpTransport.AttachPolicy(new HttpClient(handler), AAuthEgressPolicy.Production,
                AAuthTransportContract.InProcessOnly);
            var jwks = new JwksClient(http, timeProvider: time);
            var metadata = new MetadataClient(http, timeProvider: time);
            async Task Fetch()
            {
                if (metadataMode) await metadata.FetchAsync(new Uri("https://issuer.example/.well-known/aauth-agent.json"));
                else await jwks.ResolveKeyAsync(new Uri("https://issuer.example/jwks"), "key");
            }
            await Fetch();
            time.Advance(TimeSpan.FromSeconds(1));
            await Assert.ThrowsAsync<HttpRequestException>(Fetch);
            Assert.Equal(1, handler.Calls);
            handler.Fail = true;
            time.Advance(TimeSpan.FromSeconds(60));
            await Assert.ThrowsAsync<HttpRequestException>(Fetch);
            Assert.Equal(2, handler.Calls);
        }
    }

    private sealed class Handler(TimeProvider clock, string? cacheControl,
        int? expiresSeconds = null, int ageSeconds = 0, int dateAgeSeconds = 0) : HttpMessageHandler
    {
        private readonly AAuthKey _key = AAuthKey.Generate();
        public int Calls { get; private set; }
        public bool Fail { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            if (Fail) throw new HttpRequestException("offline");
            var jwk = _key.ToPublicJwk();
            jwk["kid"] = "key";
            var body = request.RequestUri!.AbsolutePath.Contains(".well-known")
                ? new JsonObject { ["issuer"] = "https://issuer.example", ["jwks_uri"] = "https://issuer.example/jwks" }
                : new JsonObject { ["keys"] = new JsonArray(jwk) };
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) };
            response.Headers.Date = clock.GetUtcNow().AddSeconds(-dateAgeSeconds);
            response.Headers.Age = TimeSpan.FromSeconds(ageSeconds);
            if (cacheControl is not null) response.Headers.TryAddWithoutValidation("Cache-Control", cacheControl);
            if (expiresSeconds is { } seconds) response.Content.Headers.Expires = clock.GetUtcNow().AddSeconds(seconds);
            return Task.FromResult(response);
        }
    }
}