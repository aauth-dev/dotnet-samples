using System.Net;
using System.Net.Http.Json;
using AAuth.Events;
using AAuth.Crypto;
using AAuth.Server.Metadata;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace AAuth.Events.Tests;

public class EventsDependencyInjectionTests
{
    private sealed class UnusedProviderStore : IAgentProviderEventStore
    {
        public void Create(ProviderSubscription subscription) => throw new NotSupportedException();
        public EventAcceptance Accept(EventEnvelope envelope, DateTimeOffset now) => throw new NotSupportedException();
        public IReadOnlyList<PendingEvent> Pending(string agent, int limit = 100, string? after = null) => throw new NotSupportedException();
        public bool Acknowledge(string agent, string receipt) => throw new NotSupportedException();
    }

    [Fact(DisplayName = "AddAAuthEvents registers a shared protocol with the configured policy and clock")]
    public async Task AddAAuthEvents_RegistersProtocol()
    {
        var clock = new FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddAAuthEvents(options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            options.TimeProvider = clock;
        });
        await using var provider = services.BuildServiceProvider();

        var protocol = provider.GetRequiredService<EventsProtocol>();
        Assert.Same(protocol, provider.GetRequiredService<EventsProtocol>());
        Assert.Same(TestEgress.Policy, protocol.TokenVerifier.EgressPolicy);
        Assert.Same(clock, protocol.TokenVerifier.TimeProvider);
        Assert.Equal(2, provider.GetServices<AAuth.HttpSig.ISignatureTokenVerifier>().Count());
    }

    [Fact(DisplayName = "the event endpoint resolves the protocol and store from DI")]
    public async Task EventEndpoint_ResolvesFromDi()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthEvents(options => options.EgressPolicy = TestEgress.Policy);
        builder.Services.AddSingleton<IAgentProviderEventStore, UnusedProviderStore>();
        await using var app = builder.Build();
        app.MapAAuthEventEndpoint("/events");
        await app.StartAsync();

        using var response = await app.GetTestClient().PostAsync("/events", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact(DisplayName = "agent metadata derives event_endpoint from one mapped Events endpoint")]
    public async Task AgentMetadata_DerivesEventEndpoint()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapAAuthEventEndpoint("/events");
        app.MapAAuthAgentWellKnown(options =>
        {
            options.Issuer = "https://ap.example";
            options.SigningKeys = new AAuthSigningKeySet { ["k1"] = AAuthKey.Generate() };
        });
        await app.StartAsync();

        var doc = await app.GetTestClient().GetFromJsonAsync<System.Text.Json.Nodes.JsonObject>("/.well-known/aauth-agent.json");
        Assert.Equal("https://ap.example/events", (string?)doc!["event_endpoint"]);
        Assert.False(doc.ContainsKey("localhost_callback_allowed"));
    }

    [Fact(DisplayName = "agent metadata emits localhost_callback_allowed only when true")]
    public async Task AgentMetadata_EmitsLocalhostCallbackAllowedOnlyWhenTrue()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapAAuthAgentWellKnown(options =>
        {
            options.Issuer = "https://ap.example";
            options.SigningKeys = new AAuthSigningKeySet { ["k1"] = AAuthKey.Generate() };
            options.LocalhostCallbackAllowed = true;
        });
        await app.StartAsync();

        var doc = await app.GetTestClient().GetFromJsonAsync<System.Text.Json.Nodes.JsonObject>("/.well-known/aauth-agent.json");
        Assert.True((bool?)doc!["localhost_callback_allowed"]);
    }

    [Fact(DisplayName = "agent metadata requires explicit event_endpoint when multiple Events endpoints are mapped")]
    public void AgentMetadata_RejectsMultipleMappedEventEndpointsWithoutExplicitEndpoint()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        using var app = builder.Build();
        app.MapAAuthEventEndpoint("/events/a");
        app.MapAAuthEventEndpoint("/events/b");

        Assert.Throws<InvalidOperationException>(() => app.MapAAuthAgentWellKnown(options =>
        {
            options.Issuer = "https://ap.example";
            options.SigningKeys = new AAuthSigningKeySet { ["k1"] = AAuthKey.Generate() };
        }));
    }

    [Fact(DisplayName = "the subscription endpoint defaults its resource to the registered resource issuer")]
    public async Task SubscriptionEndpoint_DefaultsResource()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthEvents(options => options.EgressPolicy = TestEgress.Policy);
        builder.Services.AddAAuthResource(options =>
        {
            options.Issuer = "http://localhost:5005";
            options.EgressPolicy = TestEgress.Policy;
        });
        await using var app = builder.Build();

        app.MapAAuthSubscriptionEndpoint("/missing", options => options.Operation = "receive");
        app.MapAAuthSubscriptionEndpoint("/subscribe", options =>
        {
            options.Operation = "receive";
            options.ValidateParameters = _ => true;
        });
    }
}
