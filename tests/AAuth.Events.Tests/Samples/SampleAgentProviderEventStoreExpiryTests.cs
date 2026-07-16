using System.Net;
using System.Net.Http.Headers;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Events.AgentProvider;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tests.TestSupport;
using AAuth.Events.Tokens;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using MockAgentProvider.Events;

namespace AAuth.Events.Tests.Samples;

public sealed class SampleAgentProviderEventStoreExpiryTests
{
    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public async Task StaleEventWithinJwtClockSkewDoesNotExpireSubscription(
        string algorithm)
    {
        var now = EventsTestData.Now;
        var resourceKey = CreateKey(algorithm);
        var store = new SampleAgentProviderEventStore(() => now);
        Assert.True(await store.TryCreateSubscriptionAsync(new AgentProviderSubscription(
            "eid-1",
            "aauth:agent@ap.example",
            "https://resource.example",
            null,
            now.AddHours(1))));

        using var server = CreateServer(resourceKey, store, now);
        using var client = server.CreateClient();

        var stale = BuildEvent(resourceKey, now.AddMinutes(-5).AddSeconds(-10), "stale-1");
        using (var response = await client.SendAsync(
            SignedBodylessEvent(resourceKey, stale.CompactToken, now)))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        var pendingAfterStale = await store.ListPendingAsync("aauth:agent@ap.example", 10);
        Assert.Single(pendingAfterStale);
        Assert.Equal(stale.CompactToken, pendingAfterStale[0].EventToken);

        var fresh1 = BuildEvent(resourceKey, now, "fresh-1");
        using (var response = await client.SendAsync(
            SignedBodylessEvent(resourceKey, fresh1.CompactToken, now)))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        var pendingAfterFresh1 = await store.ListPendingAsync("aauth:agent@ap.example", 10);
        Assert.Equal(2, pendingAfterFresh1.Count);
        Assert.Contains(pendingAfterFresh1, receipt => receipt.EventToken == stale.CompactToken);
        Assert.Contains(pendingAfterFresh1, receipt => receipt.EventToken == fresh1.CompactToken);

        var outsideSkew = BuildEvent(resourceKey, now.AddMinutes(-5).AddSeconds(-45), "outside-skew");
        using (var response = await client.SendAsync(
            SignedBodylessEvent(resourceKey, outsideSkew.CompactToken, now)))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        var pendingAfterRejected = await store.ListPendingAsync("aauth:agent@ap.example", 10);
        Assert.Equal(2, pendingAfterRejected.Count);
        Assert.Contains(pendingAfterRejected, receipt => receipt.EventToken == stale.CompactToken);
        Assert.Contains(pendingAfterRejected, receipt => receipt.EventToken == fresh1.CompactToken);

        var fresh2 = BuildEvent(resourceKey, now, "fresh-2");
        using (var response = await client.SendAsync(
            SignedBodylessEvent(resourceKey, fresh2.CompactToken, now)))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        var pendingAfterFresh2 = await store.ListPendingAsync("aauth:agent@ap.example", 10);
        Assert.Equal(3, pendingAfterFresh2.Count);
        Assert.Contains(pendingAfterFresh2, receipt => receipt.EventToken == stale.CompactToken);
        Assert.Contains(pendingAfterFresh2, receipt => receipt.EventToken == fresh1.CompactToken);
        Assert.Contains(pendingAfterFresh2, receipt => receipt.EventToken == fresh2.CompactToken);
    }

    [Fact]
    public async Task ReceiptRetentionEventuallyRemovesReceiptsAndBoundsReplay()
    {
        var now = EventsTestData.Now;
        var current = now;
        DateTimeOffset Clock() => current;
        var store = new SampleAgentProviderEventStore(Clock, TimeSpan.FromMinutes(1));
        Assert.True(await store.TryCreateSubscriptionAsync(new AgentProviderSubscription(
            "eid-1",
            "aauth:agent@ap.example",
            "https://resource.example",
            null,
            now.AddHours(1))));

        var staleClaims = new EventTokenClaims(
            "https://resource.example",
            "aauth:agent@ap.example",
            "eid-1",
            "stale-1",
            now.AddMinutes(-5),
            now.AddSeconds(-10),
            "resource-1");
        var incoming = new IncomingEvent(
            "header.payload.signature",
            staleClaims,
            System.Text.Encoding.UTF8.GetBytes("payload"),
            receiptTime: now);

        var accepted = await store.AcceptEventAsync(incoming);
        Assert.Equal(EventAcceptanceOutcome.Accepted, accepted.Outcome);
        Assert.Single(await store.ListPendingAsync("aauth:agent@ap.example", 10));

        var duplicate = await store.AcceptEventAsync(incoming);
        Assert.Equal(EventAcceptanceOutcome.AlreadyAccepted, duplicate.Outcome);

        current = now.AddMinutes(1).AddSeconds(1);
        Assert.Empty(await store.ListPendingAsync("aauth:agent@ap.example", 10));
        Assert.False(await store.AcknowledgeAsync("aauth:agent@ap.example", incoming.TokenHashHex));

        var replay = new IncomingEvent(
            incoming.CompactToken,
            staleClaims,
            System.Text.Encoding.UTF8.GetBytes("payload"),
            receiptTime: current);
        var replayAccepted = await store.AcceptEventAsync(replay);
        Assert.Equal(EventAcceptanceOutcome.Accepted, replayAccepted.Outcome);
        Assert.Single(await store.ListPendingAsync("aauth:agent@ap.example", 10));
        Assert.True(await store.AcknowledgeAsync("aauth:agent@ap.example", replay.TokenHashHex));
    }

    private static TestServer CreateServer(
        IAAuthKey resourceKey,
        IAAuthAgentProviderEventStore store,
        DateTimeOffset now)
    {
        var resolver = CreateResolver(resourceKey, now);
        var verifier = new EventsHttpMessageVerifier
        {
            Clock = () => now,
            MaxAge = TimeSpan.FromMinutes(5),
        };

        return new TestServer(new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddSingleton<IAAuthAgentProviderEventStore>(store);
            })
            .Configure(app => app.UseRouting().UseEndpoints(endpoints =>
                endpoints.MapAAuthEventEndpoint("/events", options =>
                {
                    options.JwtKeyResolver = resolver;
                    options.HttpMessageVerifier = verifier;
                    options.Clock = () => now;
                }))));
    }

    private static EventsJwtKeyResolver CreateResolver(IAAuthKey resourceKey, DateTimeOffset now)
    {
        var handler = new ResourceDiscoveryHandler(resourceKey);
        return new EventsJwtKeyResolver(
            new HttpClient(handler),
            new DefaultEventsUrlPolicy(),
            new TokenVerifier
            {
                Clock = () => now,
                ClockSkew = TimeSpan.FromSeconds(30),
            });
    }

    private static EventTokenArtifact BuildEvent(IAAuthKey signingKey, DateTimeOffset issuedAt, string jti) =>
        new EventTokenBuilder
        {
            Issuer = "https://resource.example",
            Audience = "aauth:agent@ap.example",
            Eid = "eid-1",
            KeyId = "resource-1",
            Key = signingKey,
            IssuedAt = issuedAt,
            Lifetime = TimeSpan.FromMinutes(5),
            Jti = jti,
        }.Build();

    private static HttpRequestMessage SignedBodylessEvent(
        IAAuthKey signingKey,
        string compactToken,
        DateTimeOffset now)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost/events");
        new EventsRequestSigner(signingKey, () => compactToken, () => now)
            .SignBodyless(request);
        return request;
    }

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "ES256" ? EcdsaAAuthKey.Generate() : AAuthKey.Generate();

    private sealed class ResourceDiscoveryHandler(IAAuthKey key) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var jwk = key.ToPublicJwk();
            jwk["kid"] = "resource-1";
            jwk["use"] = "sig";
            jwk["alg"] = key.Algorithm;

            return Task.FromResult(request.RequestUri?.AbsoluteUri switch
            {
                "https://resource.example/.well-known/aauth-resource.json" =>
                    JsonResponse(new System.Text.Json.Nodes.JsonObject
                    {
                        ["issuer"] = "https://resource.example",
                        ["jwks_uri"] = "https://resource.example/jwks",
                    }),
                "https://resource.example/jwks" =>
                    JsonResponse(new System.Text.Json.Nodes.JsonObject
                    {
                        ["keys"] = new System.Text.Json.Nodes.JsonArray { jwk },
                    }),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            });
        }

        private static HttpResponseMessage JsonResponse(System.Text.Json.Nodes.JsonObject body) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(body.ToJsonString(), System.Text.Encoding.UTF8,
                    AAuthEventsConstants.JsonMediaType),
            };
    }
}
