namespace AAuth.Samples.Events;

public static class EventDemoCode
{
    public static readonly string[] Steps = [Discover, SubscriptionUrl, SubscribeToken, Registration, Delivery, Receipt];
    public const string Discover = """
        public static async Task<JsonObject> DiscoverChannelsAsync(HttpClient http,
            EventsProtocol protocol, string resource, string provider, CancellationToken cancellationToken)
        {
            using var metadata = new MetadataClient(http);
            var resourceMetadata = await metadata.FetchAsync(
                new Uri(resource + "/.well-known/aauth-resource.json"), cancellationToken);
            var documentUrl = resourceMetadata["r3_vocabularies"]!["urn:aauth:vocabulary:asyncapi"]!.GetValue<string>();
            var channels = await http.GetFromJsonAsync<JsonObject>(
                new Uri(new Uri(resource), documentUrl), cancellationToken);
            var eventEndpoint = await protocol.ResolveEventEndpointAsync(provider, cancellationToken);
            return channels!;
        }
        """;
    public const string SubscriptionUrl = """
        public static async Task<(string Agent, string AgentToken, string SubscriptionUrl)> ObtainSubscriptionUrlAsync(AAuthKey key,
            string provider, string person, string resource, string account, bool protectedChannel,
            string publicSubscriptionUrl, AAuthEgressPolicy policy,
            Func<Interaction, CancellationToken, Task> showConsent, CancellationToken cancellationToken)
        {
            var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol")
                .WithKey(key).WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person)
                .WithEgressPolicy(policy).EnrolAsync(cancellationToken);
            if (!protectedChannel) return (enrolled.AgentId!, enrolled.AgentToken!, publicSubscriptionUrl);
            using var agent = new AAuthClientBuilder(key).UseJwt(enrolled.AgentToken!)
                .WithEgressPolicy(policy).WithChallengeHandling(person,
                    options => options.OnInteractionRequired = showConsent).Build();
            using var request = new HttpRequestMessage(HttpMethod.Get,
                resource + "/search_availability?account=" + Uri.EscapeDataString(account));
            request.Options.Set(AAuthRequestOptions.Account, account);
            using var response = await agent.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
            return (enrolled.AgentId!, enrolled.AgentToken!, result!["notifications"]!["subscribe_url"]!.GetValue<string>());
        }
        """;
    public const string SubscribeToken = """
        public static async Task<JsonObject> AcquireSubscribeTokenAsync(EventsProtocol protocol,
            IAgentEventStore store, IAAuthSigner key, string agentToken, string agent,
            string provider, string resource, string context, CancellationToken cancellationToken)
        {
            var body = System.Text.Encoding.UTF8.GetBytes(new JsonObject
                { ["resource"] = resource, ["max_uses"] = 1 }.ToJsonString());
            using var response = await protocol.SendAsync(HttpMethod.Post,
                new Uri(provider + "/local/events/subscribe"), key, agentToken,
                selfIssued: false, body: body, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
            var result = (await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken))!;
            store.Remember(new(result["eid"]!.GetValue<string>(), resource, agent, context));
            return result;
        }
        """;
    public const string Registration = """
        public static async Task RegisterSubscriptionAsync(EventsProtocol protocol,
            Uri subscriptionUrl, IAAuthSigner key, string subscribeToken, CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Post, subscriptionUrl,
                key, subscribeToken, selfIssued: false,
                body: "{\"event_types\":[\"reservation.available\"]}"u8.ToArray(),
                cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        """;
    public const string Delivery = """
        public static async Task TriggerSampleEventAsync(EventsProtocol protocol, string resource,
            string eid, IAAuthSigner agentKey, string agentToken, string? account, CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Post,
                new Uri(resource + "/local/events/" + eid + "/notify"
                    + (account is null ? "" : "?account=" + Uri.EscapeDataString(account))), agentKey, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }

        public static async Task DeliverResourceEventAsync(EventsProtocol protocol, string resource,
            string provider, string agent, string eid, IAAuthSigner resourceKey, string resourceKid,
            byte[] payload, CancellationToken cancellationToken)
        {
            var token = await new EventTokenBuilder
            {
                Issuer = resource, Audience = agent, Eid = eid, Key = resourceKey,
                KeyId = resourceKid, Verifier = protocol.TokenVerifier,
            }.BuildAsync(cancellationToken);
            var endpoint = await protocol.ResolveEventEndpointAsync(provider, cancellationToken);
            using var response = await protocol.SendAsync(HttpMethod.Post, endpoint,
                resourceKey, token, selfIssued: true, body: payload, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        """;
    public const string Receipt = """
        public static async Task VerifyInboxAsync(EventsProtocol protocol, IAgentEventStore store,
            string provider, string agent, string eid, IAAuthSigner key, string agentToken,
            CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Get,
                new Uri(provider + "/local/events/inbox"), key, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
            var pending = (await response.Content.ReadFromJsonAsync<PendingEvent[]>(cancellationToken))!;
            var item = pending.Single(delivery => delivery.Event.Eid == eid);
            var receiver = new EventReceiver(protocol, store, agent);
            await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
            var duplicate = await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
            if (duplicate) throw new InvalidOperationException("Duplicate event was not suppressed.");
            using var acknowledged = await protocol.SendAsync(HttpMethod.Post,
                new Uri(provider + "/local/events/inbox/" + item.Receipt + "/ack"), key, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            acknowledged.EnsureSuccessStatusCode();
        }
        """;

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
        var eventToken = await new EventTokenBuilder
        {
            Issuer = resource, Audience = agent, Eid = subscription.Eid,
            Key = resourceKey, KeyId = resourceKid,
            Verifier = protocol.TokenVerifier
        }.BuildAsync();
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