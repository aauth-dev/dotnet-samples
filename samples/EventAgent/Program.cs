using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using AAuth;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Agent;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.HttpSig;

const string DefaultAp = "http://localhost:5301";
const string DefaultBookings = "http://localhost:5005";
const string DefaultPs = "http://localhost:5100";
const string DefaultSubject = "aauth:event-agent@ap.example";
const string Usage = """
Usage: EventAgent [options]

Runs the protected Bookings waitlist and AAuth Events flow.

Options:
  --ap <url>        Agent Provider (default: http://localhost:5301)
  --bookings <url> Bookings resource (default: http://localhost:5005)
  --ps <url>        Person Server (default: http://localhost:5100)
  --sub <subject>   Agent subject (default: aauth:event-agent@ap.example)
  -h, --help        Show this usage
""";

Options options;
try
{
    options = ParseOptions(args);
}
catch (ArgumentException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 2;
}
if (options.ShowHelp)
{
    Console.WriteLine(Usage);
    return 0;
}

try
{
    await RunAsync(options);
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"EventAgent failed: {exception.Message}");
    return 1;
}

static Options ParseOptions(string[] args)
{
    var ap = DefaultAp;
    var bookings = DefaultBookings;
    var ps = DefaultPs;
    var subject = DefaultSubject;

    for (var index = 0; index < args.Length; index++)
    {
        var option = args[index];
        if (option is "-h" or "--help")
            return new Options(ap, bookings, ps, subject, true);

        if (option is not ("--ap" or "--bookings" or "--ps" or "--sub"))
            throw new ArgumentException($"Unknown option '{option}'.\n\n{Usage}");
        if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException($"Missing value for {option}.\n\n{Usage}");

        switch (option)
        {
            case "--ap": ap = args[index]; break;
            case "--bookings": bookings = args[index]; break;
            case "--ps": ps = args[index]; break;
            case "--sub": subject = args[index]; break;
        }
    }

    ValidateOptionUri(ap, "--ap");
    ValidateOptionUri(bookings, "--bookings");
    ValidateOptionUri(ps, "--ps");
    if (string.IsNullOrWhiteSpace(subject))
        throw new ArgumentException("--sub must not be empty.");
    if (subject.Contains('/', StringComparison.Ordinal) ||
        subject.Contains('?', StringComparison.Ordinal) ||
        subject.Contains('#', StringComparison.Ordinal))
        throw new ArgumentException("--sub must be a single URL path segment.");
    return new Options(ap.TrimEnd('/'), bookings.TrimEnd('/'), ps.TrimEnd('/'), subject, false);
}

static void ValidateOptionUri(string value, string option)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out _))
        throw new ArgumentException($"{option} must be an absolute URL: {value}");
}

static async Task RunAsync(Options options)
{
    using var discoveryHttp = new HttpClient();
    var metadataClient = new MetadataClient(discoveryHttp);
    var metadata = await metadataClient.FetchAsync(
        MetadataClient.BuildUrl(options.Ap, "aauth-agent.json"));
    var enrolEndpoint = RequiredUri(metadata, "enrol_endpoint", $"{options.Ap}/enrol");
    var refreshEndpoint = RequiredUri(metadata, "refresh_endpoint", $"{options.Ap}/refresh");

    var keyStore = FileKeyStore.Default();
    var cacheDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "aauth-event-agent");
    var cacheFile = Path.Combine(cacheDirectory, CacheName(options.Subject) + ".json");

    var enrollment = await LoadOrEnrollAsync(
        options, keyStore, enrolEndpoint, refreshEndpoint, cacheFile);
    Console.WriteLine($"Enrolled agent: {options.Subject}");
    Console.WriteLine($"Durable key handle: {enrollment.LocalKeyHandle}");

    var tokenRefresher = AgentProviderTokenRefresher.Create(
            enrollment.RefreshEndpoint, enrollment.LocalKeyHandle)
        .WithKeyStore(keyStore)
        .Build();

    var clientBuilder = new AAuthClientBuilder(enrollment.Key)
        .WithTokenRefresh(tokenRefresher)
        .WithChallengeHandling(options.PersonServer, challengeOptions =>
        {
            challengeOptions.MinPollInterval = TimeSpan.FromMilliseconds(200);
            challengeOptions.OnPoll = response =>
                Console.WriteLine($"  [auth poll] {(int)response.StatusCode}");
            challengeOptions.OnInteractionRequired = (interaction, _) =>
            {
                Console.WriteLine($"  [interaction] Approval may be required: {interaction.BuildUserUrl()}");
                return Task.CompletedTask;
            };
        });
    using var bookingsClient = clientBuilder.Build();

    var requestUrl = new Uri($"{options.Bookings}/waitlist/request");
    Console.WriteLine($"POST {requestUrl} (AAuth challenge handling)");
    using var waitlistRequest = new HttpRequestMessage(HttpMethod.Post, requestUrl);
    using var waitlistResponse = await bookingsClient.SendAsync(waitlistRequest);
    await EnsureSuccessAsync(waitlistResponse, "waitlist request");
    var waitlist = await ReadJsonAsync<WaitlistResponse>(waitlistResponse, "waitlist response");
    var subscribeUrl = ParseAbsoluteUri(waitlist.Waitlist?.SubscribeUrl, "waitlist.subscribe_url");
    Console.WriteLine($"Protected subscribe URL: {subscribeUrl}");

    var acquisitionUrl = new Uri(
        $"{options.Ap}/agents/{options.Subject}/event-subscriptions/bookings");
    Console.WriteLine($"POST {acquisitionUrl} (signed bodyless AP acquisition)");
    using var acquisitionResponse = await SendSignedBodylessAsync(
        acquisitionUrl, HttpMethod.Post, enrollment.Key);
    await EnsureSuccessAsync(acquisitionResponse, "subscribe-token acquisition");
    var acquisition = await ReadJsonAsync<AcquisitionResponse>(
        acquisitionResponse, "subscribe-token acquisition response");
    if (string.IsNullOrWhiteSpace(acquisition.SubscribeToken) ||
        string.IsNullOrWhiteSpace(acquisition.Eid))
    {
        throw new InvalidOperationException(
            "The AP acquisition response must contain subscribe_token and eid.");
    }

    var contexts = new Dictionary<string, EventContext>(StringComparer.Ordinal)
    {
        [acquisition.Eid] = new EventContext(
            acquisition.Eid,
            options.Subject,
            options.Bookings,
            subscribeUrl.ToString()),
    };
    Console.WriteLine($"Acquired subscribe token for eid={acquisition.Eid}");

    using var registrationHttp = new HttpClient();
    var registrationClient = new SubscriptionRegistrationClient(
        registrationHttp, enrollment.Key);
    var registrationBody = """{"event_types":["slot.available"]}""";
    Console.WriteLine($"POST {subscribeUrl} (ticket registration)");
    var registration = await registrationClient.RegisterJsonAsync(
        subscribeUrl, acquisition.SubscribeToken, registrationBody);
    Console.WriteLine($"Registered event types: {string.Join(", ", registration.SelectedEventTypes)}");

    var triggerUrl = new Uri(
        $"{options.Bookings}/waitlist/subscriptions/{Uri.EscapeDataString(acquisition.Eid)}/trigger");
    Console.WriteLine($"POST {triggerUrl} (deterministic trigger)");
    using var triggerRequest = new HttpRequestMessage(HttpMethod.Post, triggerUrl);
    using var triggerResponse = await bookingsClient.SendAsync(triggerRequest);
    await EnsureSuccessAsync(triggerResponse, "event trigger");

    var eventsUrl = new Uri(
        $"{options.Ap}/agents/{options.Subject}/events?limit=20");
    Console.WriteLine($"GET {eventsUrl} (signed batch poll)");
    using var pollResponse = await SendSignedBodylessAsync(
        eventsUrl, HttpMethod.Get, enrollment.Key);
    await EnsureSuccessAsync(pollResponse, "event poll");
    var receipts = await ReadJsonAsync<List<EventReceipt>>(pollResponse, "event poll response")
        ?? throw new InvalidOperationException("The event poll response must be a JSON array.");

    using var eventsHttp = EventsHttpClientFactory.Create(new DefaultEventsUrlPolicy());
    var verifier = new EventTokenVerifier(
        new EventsJwtKeyResolver(eventsHttp),
        options.Subject,
        (string eid) => contexts.TryGetValue(eid, out var context)
            ? context
            : null,
        new InMemoryEventDeduplicator());

    var failures = new List<Exception>();
    foreach (var receipt in receipts)
    {
        try
        {
            await ProcessReceiptAsync(
                receipt, verifier, options.Ap, options.Subject, enrollment.Key);
        }
        catch (Exception exception)
        {
            failures.Add(new InvalidOperationException(
                $"Receipt '{receipt.ReceiptId}' was not acknowledged: {exception.Message}",
                exception));
            Console.Error.WriteLine($"Receipt '{receipt.ReceiptId}' failed: {exception.Message}");
        }
    }

    if (failures.Count != 0)
        throw new AggregateException("One or more event receipts failed processing.", failures);
    if (receipts.Count == 0)
        throw new InvalidOperationException("The AP returned no pending event receipts.");

    Console.WriteLine("Event flow completed.");
}

static async Task<Enrollment> LoadOrEnrollAsync(
    Options options,
    IKeyStore keyStore,
    Uri enrolEndpoint,
    Uri refreshEndpoint,
    string cacheFile)
{
    if (File.Exists(cacheFile))
    {
            var cached = JsonNode.Parse(await File.ReadAllTextAsync(cacheFile)) as JsonObject
            ?? throw new InvalidOperationException($"Enrollment cache is not a JSON object: {cacheFile}");
            var cachedSubject = (string?)cached["subject"];
            var cachedPersonServer = (string?)cached["person_server"];
            var handle = (string?)cached["key_id"];
        if (cachedSubject == options.Subject &&
            cachedPersonServer == options.PersonServer &&
            !string.IsNullOrWhiteSpace(handle))
        {
            var key = await keyStore.LoadAsync(handle);
            if (key is not null)
            {
                Console.WriteLine("Loaded durable enrollment cache; refreshing agent token.");
                _ = await new AgentProviderClient(new HttpClient(), keyStore)
                    .RefreshAsync(refreshEndpoint.ToString(), handle);
                return new Enrollment(
                    key,
                    handle,
                    (string?)cached["agent_token_kid"],
                    RequiredUri(cached, "jwks_uri", null),
                    refreshEndpoint.ToString());
            }
        }

        Console.WriteLine("Enrollment cache is stale or its key is unavailable; re-enrolling.");
    }

    var apClient = new AgentProviderClient(new HttpClient(), keyStore);
    var result = await apClient.EnrolAsync(
        options.Ap,
        options.Subject,
        enrolEndpoint.ToString(),
        options.PersonServer);
    var resolvedJwksUri = ParseAbsoluteUri(
        result.JwksUri, "AP enrollment jwks_uri");

    Directory.CreateDirectory(Path.GetDirectoryName(cacheFile)!);
    var cache = new JsonObject
    {
        ["subject"] = options.Subject,
        ["person_server"] = options.PersonServer,
        ["key_id"] = result.LocalKeyHandle,
        ["agent_token_kid"] = result.AgentTokenKid,
        ["jwks_uri"] = resolvedJwksUri.ToString(),
        ["refresh_endpoint"] = refreshEndpoint.ToString(),
    };
    await File.WriteAllTextAsync(cacheFile, cache.ToJsonString(new JsonSerializerOptions
    {
        WriteIndented = true,
    }));
    return new Enrollment(
        result.Key,
        result.LocalKeyHandle,
        result.AgentTokenKid,
        resolvedJwksUri,
        refreshEndpoint.ToString());
}

static async Task ProcessReceiptAsync(
    EventReceipt receipt,
    EventTokenVerifier verifier,
    string apUrl,
    string agentId,
    IAAuthKey key)
{
    if (string.IsNullOrWhiteSpace(receipt.ReceiptId) ||
        string.IsNullOrWhiteSpace(receipt.EventToken))
        throw new InvalidOperationException("Receipt is missing receipt_id or event_token.");

    var payload = (UnauthenticatedEventPayload?)null;
    var displayJson = (string?)null;
    var emptyPayload = false;
    if (receipt.ContentType is null)
    {
        if (receipt.PayloadBase64Url is not null)
            throw new InvalidOperationException(
                "Event receipt payload_base64url is present but content_type is null.");
    }
    else
    {
        var mediaType = receipt.ContentType.Split(';', 2)[0].Trim();
        if (!string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Event payload content type is unsupported: {receipt.ContentType}.");

        byte[] payloadBytes;
        if (string.IsNullOrEmpty(receipt.PayloadBase64Url))
        {
            emptyPayload = true;
            payloadBytes = Array.Empty<byte>();
        }
        else
        {
            payloadBytes = DecodeBase64Url(receipt.PayloadBase64Url);
        }
        payload = new UnauthenticatedEventPayload(payloadBytes, receipt.ContentType);
        if (!emptyPayload)
            displayJson = ParseDisplayJson(payload.GetUtf8Text());
    }

    var result = await verifier.VerifyAsync(receipt.EventToken, payload);
    if (result.Status is not AgentEventVerificationStatus.Verified ||
        result.Event is null)
        throw new InvalidOperationException(
            $"Event verification was not actionable: {result.Status} ({result.Detail}).");

    var context = (EventContext)result.Event.Context;
    Console.WriteLine($"Verified event: eid={result.Claims.Eid}, jti={result.Claims.Jti}");
    Console.WriteLine($"Context: resource={context.Resource}, subscribe_url={context.SubscribeUrl}");
    if (payload is null)
    {
        Console.WriteLine("NO PAYLOAD (bodyless event; no consequential action).");
    }
    else if (emptyPayload)
    {
        Console.WriteLine("EMPTY PAYLOAD (display only; no consequential action).");
    }
    else
    {
        Console.WriteLine("UNAUTHENTICATED PAYLOAD (display only; no consequential action):");
        Console.WriteLine(displayJson);
    }

    var ackUrl = new Uri(
        $"{apUrl.TrimEnd('/')}/agents/{agentId}/events/{Uri.EscapeDataString(receipt.ReceiptId)}/ack");
    Console.WriteLine($"POST {ackUrl} (signed bodyless ACK)");
    using var response = await SendSignedBodylessAsync(ackUrl, HttpMethod.Post, key);
    await EnsureSuccessAsync(response, "event ACK");
}

static string ParseDisplayJson(string text)
{
    try
    {
        var node = JsonNode.Parse(text)
            ?? throw new JsonException("Payload JSON is null.");
        return node.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
    catch (JsonException exception)
    {
        throw new InvalidOperationException(
            "The unauthenticated event payload is not valid JSON and was not displayed or acknowledged.",
            exception);
    }
}

static async Task<HttpResponseMessage> SendSignedBodylessAsync(
    Uri uri, HttpMethod method,     IAAuthKey key)
{
    var handler = new AAuthSigningHandler(key, new HwkSignatureKeyProvider(key))
    {
        InnerHandler = new HttpClientHandler { AllowAutoRedirect = false },
    };
    var client = new HttpClient(handler);
    var request = new HttpRequestMessage(method, uri);
    try
    {
        var response = await client.SendAsync(request);
        request = null!;
        return response;
    }
    finally
    {
        request?.Dispose();
        client.Dispose();
    }
}

static async Task EnsureSuccessAsync(HttpResponseMessage response, string operation)
{
    if ((int)response.StatusCode is >= 200 and < 300)
        return;
    var body = response.Content is null
        ? string.Empty
        : await response.Content.ReadAsStringAsync();
    throw new HttpRequestException(
        $"{operation} returned {(int)response.StatusCode} {response.ReasonPhrase}: {body}",
        null,
        response.StatusCode);
}

static async Task<T> ReadJsonAsync<T>(HttpResponseMessage response, string operation)
{
    try
    {
        return await response.Content.ReadFromJsonAsync<T>()
            ?? throw new InvalidOperationException($"{operation} was empty.");
    }
    catch (JsonException exception)
    {
        throw new InvalidOperationException($"{operation} was not valid JSON.", exception);
    }
}

static Uri RequiredUri(JsonObject json, string property, string? fallback)
{
    var value = (string?)json[property] ?? fallback;
    return ParseAbsoluteUri(value, property);
}

static Uri ParseAbsoluteUri(string? value, string property)
{
    if (string.IsNullOrWhiteSpace(value) ||
        !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
        uri.UserInfo.Length != 0 ||
        (uri.Scheme != Uri.UriSchemeHttps &&
         !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
        throw new InvalidOperationException($"{property} must be an absolute HTTPS or loopback HTTP URL.");
    return uri;
}

static string CacheName(string subject) =>
    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(subject))).ToLowerInvariant();

static byte[] DecodeBase64Url(string value)
{
    if (string.IsNullOrWhiteSpace(value))
        throw new InvalidOperationException("payload_base64url must not be empty.");
    var base64 = value.Replace('-', '+').Replace('_', '/');
    base64 += (base64.Length % 4) switch
    {
        0 => string.Empty,
        2 => "==",
        3 => "=",
        _ => throw new InvalidOperationException("payload_base64url has invalid padding."),
    };
    try
    {
        return Convert.FromBase64String(base64);
    }
    catch (FormatException exception)
    {
        throw new InvalidOperationException("payload_base64url is malformed.", exception);
    }
}

sealed record Options(
    string Ap,
    string Bookings,
    string PersonServer,
    string Subject,
    bool ShowHelp);

sealed record Enrollment(
    IAAuthKey Key,
    string LocalKeyHandle,
    string? AgentTokenKid,
    Uri JwksUri,
    string RefreshEndpoint);

sealed record EventContext(
    string Eid,
    string Agent,
    string Resource,
    string SubscribeUrl);

sealed record WaitlistResponse(
    string? Status,
    WaitlistDetails? Waitlist);

sealed record WaitlistDetails(
    [property: JsonPropertyName("subscribe_url")] string? SubscribeUrl,
    [property: JsonPropertyName("event_types")] string[]? EventTypes,
    [property: JsonPropertyName("offer_window_seconds")] int? OfferWindowSeconds);

sealed record AcquisitionResponse(
    [property: JsonPropertyName("subscribe_token")] string? SubscribeToken,
    string? Eid,
    [property: JsonPropertyName("expires_at")] DateTimeOffset? ExpiresAt);

sealed record EventReceipt(
    [property: JsonPropertyName("receipt_id")] string? ReceiptId,
    [property: JsonPropertyName("event_token")] string? EventToken,
    [property: JsonPropertyName("payload_base64url")] string? PayloadBase64Url,
    [property: JsonPropertyName("content_type")] string? ContentType,
    [property: JsonPropertyName("received_at")] DateTimeOffset? ReceivedAt);
