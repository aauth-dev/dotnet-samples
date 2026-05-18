using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using Xunit;

namespace AAuth.Tests.Discovery;

public class JwksClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public Func<int, string> Body { get; set; } = _ => "{\"keys\":[]}";
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Body(Calls), Encoding.UTF8, "application/json"),
            });
        }
    }

    private static string JwksOf(string kid, AAuthKey key)
    {
        var jwk = key.ToPublicJwk();
        jwk["kid"] = kid;
        jwk["alg"] = AAuthKey.Algorithm;
        jwk["use"] = "sig";
        var keys = new System.Text.Json.Nodes.JsonArray { jwk };
        var doc = new System.Text.Json.Nodes.JsonObject { ["keys"] = keys };
        return doc.ToJsonString();
    }

    [Fact]
    public async Task ResolveKey_ReturnsMatchingKid()
    {
        var key = AAuthKey.Generate();
        var stub = new StubHandler { Body = _ => JwksOf("k1", key) };
        var client = new JwksClient(new HttpClient(stub));

        var resolved = await client.ResolveKeyAsync(new Uri("https://ps.example/jwks"), "k1");
        Assert.NotNull(resolved);
        Assert.Equal(key.ComputeJwkThumbprint(), resolved!.ComputeJwkThumbprint());
    }

    [Fact]
    public async Task ResolveKey_ReturnsNullForUnknownKidWithinRateLimit()
    {
        var key = AAuthKey.Generate();
        var time = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var stub = new StubHandler { Body = _ => JwksOf("k1", key) };
        var client = new JwksClient(new HttpClient(stub), minRefreshInterval: TimeSpan.FromMinutes(1), clock: () => time);

        await client.ResolveKeyAsync(new Uri("https://ps.example/jwks"), "k1"); // primes cache.
        var result = await client.ResolveKeyAsync(new Uri("https://ps.example/jwks"), "kX");

        Assert.Null(result);
        Assert.Equal(1, stub.Calls); // no refresh within rate-limit window.
    }

    [Fact]
    public async Task ResolveKey_RefreshesAfterRateLimit()
    {
        var oldKey = AAuthKey.Generate();
        var newKey = AAuthKey.Generate();
        var time = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var stub = new StubHandler
        {
            Body = call => call == 1 ? JwksOf("k1", oldKey) : JwksOf("k2", newKey),
        };
        var client = new JwksClient(new HttpClient(stub),
            minRefreshInterval: TimeSpan.FromMinutes(1),
            clock: () => time);

        await client.ResolveKeyAsync(new Uri("https://ps.example/jwks"), "k1");
        time = time.AddMinutes(2);
        var resolved = await client.ResolveKeyAsync(new Uri("https://ps.example/jwks"), "k2");

        Assert.NotNull(resolved);
        Assert.Equal(2, stub.Calls);
    }
}
