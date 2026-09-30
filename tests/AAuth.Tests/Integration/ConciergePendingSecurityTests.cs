using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Integration;

public class ConciergePendingSecurityTests
{
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
        var pending = factory.Services.GetRequiredService<Concierge.PendingStore>().Add(original, person + "/interaction", "ABCDEFGH");
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