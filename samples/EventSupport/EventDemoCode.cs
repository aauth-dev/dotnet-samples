namespace AAuth.Samples.Events;

public static class EventDemoCode
{
    public const string Example = """
        builder.Services.AddAAuthEvents();
        var app = builder.Build();
        using var http = AAuthHttpTransport.CreateClient(egressPolicy);
        var protocol = new EventsProtocol(http,
            app.Services.GetServices<ISignatureTokenVerifier>());

        // Public registration uses an AsyncAPI channel URL; protected
        // registration uses the ticket from an authorized Bookings response.
        using var registration = await protocol.SendAsync(HttpMethod.Post,
            subscriptionUrl, agentKey, subscribeToken, selfIssued: false,
            body: subscriptionParameters);

        // Resource signs both JWT and HTTP with the same discoverable key.
        var eventToken = new EventTokenBuilder
        {
            Issuer = resource, Audience = agent, Eid = subscription.Eid,
            Key = resourceKey, KeyId = resourceKid,
            Verifier = protocol.TokenVerifier
        }.Build();
        var endpoint = await protocol.ResolveEventEndpointAsync(subscription.Provider);
        using var delivery = await protocol.SendAsync(HttpMethod.Post,
            endpoint, resourceKey, eventToken, selfIssued: true, body: payloadBytes);

        // AP endpoint requires a durable transactional quota/outbox store.
        app.MapAAuthEventEndpoint("/events", protocol, providerStore);

        // Agent verifies the issuer JWT and context before persisting receipt.
        var receiver = new EventReceiver(protocol, agentStore, agent);
        var firstReceipt = await receiver.ReceiveAsync(eventToken, payloadBytes);
        """;
}