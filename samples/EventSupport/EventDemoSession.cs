using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.HttpSig;
using AAuth.Tokens;

namespace AAuth.Samples.Events;

public sealed class EventDemoSession : IDisposable
{
    private readonly HttpClient _http;
    private readonly EventsProtocol _protocol;
    private readonly SqliteEventStore _store;
    private readonly AAuthKey _key;
    private readonly string _provider;
    private readonly string _resource;
    private readonly string _person;
    private string? _agentToken;
    private string? _subscribeToken;
    private string? _subscriptionUrl;
    private string? _eventEndpoint;
    private string? _publicSubscriptionUrl;
    public string Agent { get; private set; } = "";
    public string Account { get; set; } = "personal";
    public bool Protected { get; set; } = true;
    public int Step { get; private set; }
    public string? Eid { get; private set; }
    public string? ConsentUrl { get; private set; }
    public List<EventDemoEvidence> Evidence { get; } = [];
    public string? Payload { get; private set; }
    public string? Context { get; private set; }
    public Func<Task>? Changed { get; set; }

    public static readonly string[] Steps = ["Discover event channels", "Obtain subscription URL",
        "Acquire subscribe token", "Register subscription", "Deliver sample event", "Verify inbox event"];

    public EventDemoSession(string directory, string provider = "http://localhost:5301",
        string resource = "http://localhost:5005", string person = "http://localhost:5100", HttpClient? http = null)
    {
        _http = http ?? new SampleHttpClient();
        _provider = provider.TrimEnd('/'); _resource = resource.TrimEnd('/'); _person = person.TrimEnd('/');
        _protocol = new EventsProtocol(_http, [new EventsSignatureTokenVerifier(true), new EventsSignatureTokenVerifier(false)]);
        _store = new SqliteEventStore(Path.Combine(directory, "agent.db"));
        _key = new FileKeyStore(Path.Combine(directory, "keys")).LoadOrCreate("agent");
    }

    public async Task NextAsync(CancellationToken cancellationToken = default)
    {
        switch (Step)
        {
            case 0:
                var metadata = await new MetadataClient(_http).FetchAsync(new Uri(_resource + "/.well-known/aauth-resource.json"), cancellationToken);
                var documentUrl = metadata["r3_vocabularies"]?["urn:aauth:vocabulary:asyncapi"]?.GetValue<string>()
                    ?? throw new InvalidOperationException("Resource did not advertise AsyncAPI.");
                using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(_resource), documentUrl)))
                using (var response = await AAuthHttpTransport.SendAsync(_http, request, cancellationToken))
                {
                    response.EnsureSuccessStatusCode();
                    var document = (await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken))!;
                    var address = document["channels"]?["publicAvailability"]?["address"]?.GetValue<string>()
                        ?? throw new InvalidOperationException("Public channel address is missing.");
                    _publicSubscriptionUrl = new Uri(new Uri(_resource), address).AbsoluteUri;
                    _eventEndpoint = (await _protocol.ResolveEventEndpointAsync(_provider, cancellationToken)).AbsoluteUri;
                    Evidence.Add(new(1, "GET resource metadata + AsyncAPI + AP metadata", 200,
                        new JsonObject { ["resource_metadata"] = metadata, ["asyncapi"] = document, ["event_endpoint"] = _eventEndpoint }.ToJsonString(Pretty)));
                }
                break;
            case 1:
                var enrolled = await new AgentProviderClient(_http, new InMemoryKeyStore()).EnrolWithKeyAsync(
                    _provider, null, _provider + "/enrol", _key, _person, cancellationToken);
                _agentToken = enrolled.AgentToken;
                Agent = enrolled.AgentId ?? throw new InvalidOperationException("AP did not return its assigned identity.");
                if (Protected)
                {
                    try
                    {
                        using var client = new AAuthClientBuilder(_key).WithEgressPolicy(AAuthHttpTransport.GetPolicy(_http)).UseJwt(_agentToken!)
                            .WithChallengeHandling(_person, options => options.OnInteractionRequired = async (interaction, _) =>
                            {
                                ConsentUrl = interaction.BuildUserUrl();
                                if (Changed is not null) await Changed();
                            }).Build();
                        using var search = new HttpRequestMessage(HttpMethod.Get, _resource + "/search_availability?account=" + Uri.EscapeDataString(Account));
                        search.Options.Set(AAuthRequestOptions.Account, Account);
                        using var response = await client.SendAsync(search, cancellationToken);
                        var json = await ReadAsync(response, cancellationToken);
                        _subscriptionUrl = json["notifications"]!["subscribe_url"]!.GetValue<string>();
                        if (json["account"]?.GetValue<string>() != Account) throw new InvalidOperationException("Authorized account mismatch.");
                        Evidence.Add(new(2, "GET Bookings search -> authorized ticket", (int)response.StatusCode, json.ToJsonString(Pretty)));
                    }
                    finally
                    {
                        ConsentUrl = null;
                        if (Changed is not null) await Changed();
                    }
                }
                else
                {
                    _subscriptionUrl = _publicSubscriptionUrl;
                    Evidence.Add(new(2, "Public channel URL", 200, _subscriptionUrl!));
                }
                break;
            case 2:
                using (var response = await _protocol.SendAsync(HttpMethod.Post, new(_provider + "/local/events/subscribe"), _key,
                    _agentToken!, false, Encoding.UTF8.GetBytes(new JsonObject { ["resource"] = _resource, ["max_uses"] = 1 }.ToJsonString()), cancellationToken))
                {
                    var json = await ReadAsync(response, cancellationToken);
                    _subscribeToken = json["subscribe_token"]!.GetValue<string>();
                    Eid = json["eid"]!.GetValue<string>();
                    Context = Protected ? Account + " reservations" : "public availability";
                    _store.Remember(new(Eid, _resource, Agent, Context));
                    Evidence.Add(new(3, "POST AP local subscribe-token endpoint (jwt)", (int)response.StatusCode, json.ToJsonString(Pretty)));
                }
                break;
            case 3:
                using (var response = await _protocol.SendAsync(HttpMethod.Post, new(_subscriptionUrl!), _key, _subscribeToken!, false,
                    "{\"event_types\":[\"reservation.available\"]}"u8.ToArray(), cancellationToken))
                {
                    var json = await ReadAsync(response, cancellationToken);
                    Evidence.Add(new(4, "POST resource subscription (aa-subscribe+jwt)", (int)response.StatusCode, json.ToJsonString(Pretty)));
                }
                break;
            case 4:
                using (var response = await _protocol.SendAsync(HttpMethod.Post, new(_resource + "/local/events/" + Eid + "/notify"
                    + (Protected ? "?account=" + Uri.EscapeDataString(Account) : "")),
                    _key, _agentToken!, false, cancellationToken: cancellationToken))
                {
                    var json = await ReadAsync(response, cancellationToken);
                    Evidence.Add(new(5, "Resource -> AP " + _eventEndpoint + " (self-jwt)", (int)response.StatusCode, json.ToJsonString(Pretty)));
                }
                break;
            case 5:
                {
                    var item = await FindPendingAsync(cancellationToken);
                    var receiver = new EventReceiver(_protocol, _store, Agent);
                    var processed = await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
                    var duplicate = await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
                    Payload = Encoding.UTF8.GetString(item.Event.Body);
                    using var acknowledged = await _protocol.SendAsync(HttpMethod.Post, new(_provider + "/local/events/inbox/" + item.Receipt + "/ack"),
                        _key, _agentToken!, false, cancellationToken: cancellationToken);
                    acknowledged.EnsureSuccessStatusCode();
                    Evidence.Add(new(6, "AP local polling -> agent verification -> durable receipt -> acknowledgement", 200,
                        new JsonObject { ["processed"] = processed, ["duplicate_ignored"] = !duplicate, ["eid"] = Eid,
                            ["context"] = Context, ["payload"] = JsonNode.Parse(Payload) }.ToJsonString(Pretty)));
                }
                break;
            default: return;
        }
        Step++;
    }

    private async Task<PendingEvent> FindPendingAsync(CancellationToken cancellationToken)
    {
        string? after = null;
        while (true)
        {
            using var response = await _protocol.SendAsync(HttpMethod.Get,
                new(_provider + "/local/events/inbox" + (after is null ? "" : "?after=" + Uri.EscapeDataString(after))),
                _key, _agentToken!, false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
            var pending = (await response.Content.ReadFromJsonAsync<PendingEvent[]>(cancellationToken))!;
            var item = pending.SingleOrDefault(delivery => delivery.Event.Eid == Eid);
            if (item is not null) return item;
            if (pending.Length == 0) throw new InvalidOperationException("Event is not yet in the inbox.");
            after = pending[^1].Receipt;
        }
    }

    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };
    private static async Task<JsonObject> ReadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {text}");
        return JsonNode.Parse(text)?.AsObject() ?? throw new InvalidOperationException("Missing JSON response.");
    }

    public void Dispose() => _http.Dispose();
}

public sealed record EventDemoEvidence(int Step, string Exchange, int StatusCode, string Json);