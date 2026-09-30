using System.Net;
using AAuth.Events;
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

        Assert.Throws<InvalidOperationException>(() => app.MapAAuthSubscriptionEndpoint("/missing", options => options.Operation = "receive"));
        app.MapAAuthSubscriptionEndpoint("/subscribe", options =>
        {
            options.Operation = "receive";
            options.ValidateParameters = _ => true;
        });
    }
}
