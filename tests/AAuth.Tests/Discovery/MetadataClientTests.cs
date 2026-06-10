using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Errors;
using Xunit;

namespace AAuth.Tests.Discovery;

public class MetadataClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string Body { get; init; } = "{\"issuer\":\"https://x.example\"}";
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Body, Encoding.UTF8, "application/json"),
            });
        }
    }

    [Fact]
    public void BuildUrl_AppendsWellKnown()
    {
        var url = MetadataClient.BuildUrl("https://resource.example/foo", "aauth-resource.json");
        Assert.Equal("https://resource.example/.well-known/aauth-resource.json", url.ToString());
    }

    [Fact]
    public async Task FetchAsync_CachesWithinTtl()
    {
        var stub = new StubHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var client = new MetadataClient(new HttpClient(stub), TimeSpan.FromMinutes(5), () => clock);

        var url = new Uri("https://x.example/.well-known/aauth-resource.json");
        await client.FetchAsync(url);
        await client.FetchAsync(url);

        Assert.Equal(1, stub.Calls);
    }

    [Fact]
    public async Task FetchAsync_RefreshesAfterTtl()
    {
        var stub = new StubHandler();
        var time = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var client = new MetadataClient(new HttpClient(stub), TimeSpan.FromMinutes(5), () => time);

        var url = new Uri("https://x.example/.well-known/aauth-resource.json");
        await client.FetchAsync(url);
        time = time.AddMinutes(10);
        await client.FetchAsync(url);

        Assert.Equal(2, stub.Calls);
    }

    [Fact(DisplayName = "§Metadata Documents — accepts a document whose issuer matches the fetch origin")]
    public async Task FetchAsync_AcceptsMatchingIssuer()
    {
        var stub = new StubHandler { Body = "{\"issuer\":\"https://resource.example\"}" };
        var client = new MetadataClient(new HttpClient(stub));
        var url = new Uri("https://resource.example/.well-known/aauth-resource.json");

        var doc = await client.FetchAsync(url);

        Assert.Equal("https://resource.example", (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Metadata Documents — rejects host-poisoned metadata (issuer ≠ fetch origin)")]
    public async Task FetchAsync_RejectsHostPoisonedIssuer()
    {
        // Document served from attacker.example but claiming resource.example.
        var stub = new StubHandler { Body = "{\"issuer\":\"https://resource.example\"}" };
        var client = new MetadataClient(new HttpClient(stub));
        var url = new Uri("https://attacker.example/.well-known/aauth-resource.json");

        var ex = await Assert.ThrowsAsync<AAuthMetadataException>(() => client.FetchAsync(url));
        Assert.Equal("https://resource.example", ex.ClaimedIssuer);
        Assert.Equal("https://attacker.example", ex.ExpectedIssuer);
    }

    [Fact(DisplayName = "§Metadata Documents — rejects a document with no issuer")]
    public async Task FetchAsync_RejectsMissingIssuer()
    {
        var stub = new StubHandler { Body = "{\"jwks_uri\":\"https://resource.example/.well-known/jwks.json\"}" };
        var client = new MetadataClient(new HttpClient(stub));
        var url = new Uri("https://resource.example/.well-known/aauth-resource.json");

        var ex = await Assert.ThrowsAsync<AAuthMetadataException>(() => client.FetchAsync(url));
        Assert.Null(ex.ClaimedIssuer);
    }

    [Fact(DisplayName = "§Metadata Documents — a rejected document is not cached")]
    public async Task FetchAsync_DoesNotCacheRejectedDocument()
    {
        var stub = new StubHandler { Body = "{\"issuer\":\"https://resource.example\"}" };
        var client = new MetadataClient(new HttpClient(stub));
        var url = new Uri("https://attacker.example/.well-known/aauth-resource.json");

        await Assert.ThrowsAsync<AAuthMetadataException>(() => client.FetchAsync(url));
        await Assert.ThrowsAsync<AAuthMetadataException>(() => client.FetchAsync(url));

        // Both attempts reach the network — nothing poisoned the cache.
        Assert.Equal(2, stub.Calls);
    }
}
