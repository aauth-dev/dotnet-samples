using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.Server.CallChaining;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Integration;

public class ConciergePendingSecurityTests
{
    [Fact]
    public async Task ChainedInteractionPendingBody_UsesPendingStatus()
    {
        var context = new DefaultHttpContext();
        context.RequestServices = new ServiceCollection().AddOptions().AddLogging().BuildServiceProvider();
        context.Response.Body = new MemoryStream();
        var entry = new ChainedInteractionEntry(
            "pending-test",
            "ABCDEFGH",
            "https://concierge.example/chain-interaction/pending-test",
            "/pending/pending-test",
            new Interaction("https://ps.example/interaction", "DOWNSTREAM1"),
            "test",
            new JsonObject(),
            DateTimeOffset.UtcNow.AddMinutes(10));

        await AAuthChainedInteractions.Accepted(context, entry, TestEgress.Policy).ExecuteAsync(context);

        context.Response.Body.Position = 0;
        var body = await JsonNode.ParseAsync(context.Response.Body);
        Assert.Equal(StatusCodes.Status202Accepted, context.Response.StatusCode);
        Assert.Equal("pending", (string?)body?["status"]);
        Assert.Equal("/pending/pending-test", context.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task ChainedEntry_RekeysOnNewDownstreamInteraction_AndKeepsEarlierCodesValid()
    {
        var first = new Interaction("https://ps.example/interaction", "PSCODE");
        var second = new Interaction("https://as.example/interaction/login", "ASCODE");
        var release = new TaskCompletionSource<IResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        IAAuthInteractionHandler? interactions = null;
        var operation = await AAuthChainedOperation<IResult>.StartAsync(async (handler, ct) =>
        {
            interactions = handler;
            await handler.OnInteractionRequiredAsync(first, ct);
            return await release.Task.WaitAsync(ct);
        }, DateTimeOffset.UtcNow.AddMinutes(10));
        var parked = AAuthChainedInteractions.Park("https://concierge.example", "/pending", "/chain-interaction",
            operation.Interaction!.Downstream, "test", new JsonObject(), DateTimeOffset.UtcNow.AddMinutes(10));
        var issuerKey = AAuthKey.Generate();
        var upstream = await new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://concierge.example", PersonServer = "https://ps.example",
            Subject = "aauth:owner@ap.example", AgentConfirmationKey = AAuthKey.Generate(),
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10), Key = issuerKey, KeyId = "ps-key", Scope = "concierge",
        }.BuildAsync();
        var entry = new Concierge.PendingStore().Add(upstream, parked, "/pending", operation, operation.Interaction!.Version);

        Assert.Equal(parked, entry.Interaction);
        await interactions!.OnInteractionRequiredAsync(second, default);

        var rekeyed = entry.Interaction;
        Assert.NotEqual(parked.Code, rekeyed.Code);
        Assert.Equal(parked.Id, rekeyed.Id);
        Assert.Equal(parked.PendingUrl, rekeyed.PendingUrl);
        Assert.Equal(second, rekeyed.DownstreamInteraction);
        Assert.Same(rekeyed, entry.Interaction);
        Assert.True(entry.MatchesCode(parked.Code));
        Assert.True(entry.MatchesCode(rekeyed.Code));
        Assert.False(entry.MatchesCode("WRONGCODE"));

        release.SetResult(Results.Ok());
        await operation.Completion;
    }

    [Theory]
    [InlineData("agent", "GET")]
    [InlineData("key", "GET")]
    [InlineData("grant", "GET")]
    [InlineData("agent", "DELETE")]
    [InlineData("key", "DELETE")]
    [InlineData("grant", "DELETE")]
    public async Task PendingRequiresOriginalVerifiedGrantAndRetainsCancellation(string variant, string method)
    {
        var issuerKey = AAuthKey.Generate();
        var ownerKey = AAuthKey.Generate();
        const string person = "https://ps.example";
        const string resource = "https://concierge.example";
        using var factory = new WebApplicationFactory<Concierge.Entry>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("AAuth:Issuer", resource);
            builder.UseSetting("AAuth:PersonServer", person);
            builder.ConfigureServices(services =>
            {
                services.AddSingleton(new MetadataClient(new InProcessHttpClient(new DiscoveryHandler(issuerKey))));
                services.AddSingleton(new JwksClient(new InProcessHttpClient(new DiscoveryHandler(issuerKey))));
            });
        });
        ValueTask<string> TokenAsync(AAuthKey key, string agent) => new AuthTokenBuilder
        {
            Issuer = person, Audience = resource, PersonServer = person, Subject = agent, AgentConfirmationKey = key,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10), Key = issuerKey, KeyId = "ps-key", Scope = "concierge",
        }.BuildAsync();
        const string agent = "aauth:owner@ap.example";
        var original = await TokenAsync(ownerKey, agent);
        _ = factory.Server;
        var chained = new ChainedInteractionEntry("pending-test", "ABCDEFGH", resource + "/chain-interaction/pending-test",
            "/pending/pending-test", new Interaction(person + "/interaction", "DOWNSTREAM1"), "test", new JsonObject(),
            DateTimeOffset.UtcNow.AddMinutes(10));
        var pending = factory.Services.GetRequiredService<Concierge.PendingStore>().Add(original, chained);
        var foreignKey = variant == "key" ? AAuthKey.Generate() : ownerKey;
        var foreign = await TokenAsync(foreignKey, variant == "agent" ? "aauth:foreign@ap.example" : agent);
        using var caller = new AAuthClientBuilder(foreignKey).UseJwt(foreign).WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(factory.Server.CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        using var rejected = await caller.SendAsync(new HttpRequestMessage(new HttpMethod(method), resource + "/pending/" + pending.Id));
        Assert.Equal(HttpStatusCode.Gone, rejected.StatusCode);
        Assert.False(pending.Lifecycle.Cancelled);
        using var owner = new AAuthClientBuilder(ownerKey).UseJwt(original).WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(factory.Server.CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        using var cancelled = await owner.DeleteAsync(resource + "/pending/" + pending.Id);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        using var replay = await owner.GetAsync(resource + "/pending/" + pending.Id);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    private sealed class DiscoveryHandler(AAuthKey key) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var jwk = key.ToPublicJwk(); jwk["kid"] = "ps-key";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(request.RequestUri!.AbsolutePath.EndsWith("jwks.json", StringComparison.Ordinal)
                    ? new JsonObject { ["keys"] = new JsonArray(jwk) }
                    : new JsonObject { ["issuer"] = "https://ps.example", ["jwks_uri"] = "https://ps.example/jwks.json" }),
            });
        }
    }
}