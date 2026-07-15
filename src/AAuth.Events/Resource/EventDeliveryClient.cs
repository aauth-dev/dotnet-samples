using System.Net;
using System.Net.Http;
using System.Text.Json;
using AAuth.Crypto;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Tokens;

namespace AAuth.Events.Resource;

/// <summary>Prepares and sends signed resource-to-AP Events deliveries.</summary>
public sealed class EventDeliveryClient
{
    private readonly HttpClient _http;
    private readonly EventEndpointResolver _endpointResolver;
    private readonly IAAuthKey _resourceKey;
    private readonly string _resourceKeyId;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>Creates a delivery client over a caller-owned HTTP client.</summary>
    public EventDeliveryClient(
        HttpClient http,
        EventEndpointResolver endpointResolver,
        IAAuthKey resourceKey,
        string resourceKeyId,
        Func<DateTimeOffset>? clock = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _endpointResolver = endpointResolver ?? throw new ArgumentNullException(nameof(endpointResolver));
        _resourceKey = ValidateKey(resourceKey);
        if (string.IsNullOrWhiteSpace(resourceKeyId))
            throw new ArgumentException("A resource key identifier is required.", nameof(resourceKeyId));
        _resourceKeyId = resourceKeyId;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Creates a delivery client with the resolver before the HTTP client.</summary>
    public EventDeliveryClient(
        EventEndpointResolver endpointResolver,
        HttpClient http,
        IAAuthKey resourceKey,
        string resourceKeyId,
        Func<DateTimeOffset>? clock = null)
        : this(http, endpointResolver, resourceKey, resourceKeyId, clock)
    {
    }

    /// <summary>
    /// Creates a delivery client using the Events no-redirect transport when
    /// no HTTP client is supplied.
    /// </summary>
    public EventDeliveryClient(
        EventEndpointResolver endpointResolver,
        IAAuthKey resourceKey,
        string resourceKeyId,
        HttpClient? http = null,
        Func<DateTimeOffset>? clock = null)
        : this(
            http ?? EventsHttpClientFactory.Create(),
            endpointResolver,
            resourceKey,
            resourceKeyId,
            clock)
    {
    }

    /// <summary>Prepares a bodyless event with the supplied lifetime.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        TimeSpan lifetime) =>
        Prepare(subscription, lifetime, payload: null, contentType: null);

    /// <summary>Prepares an event with exact raw UTF-8 payload bytes.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        TimeSpan lifetime,
        byte[]? payload,
        string? contentType = null,
        DateTimeOffset? issuedAt = null)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        if (lifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "The event lifetime must be positive.");
        var issued = issuedAt ?? _clock();
        return Build(subscription, issued, issued + lifetime, payload, contentType);
    }

    /// <summary>Prepares an event with raw payload bytes and a lifetime.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        byte[]? payload,
        TimeSpan lifetime,
        string? contentType = null,
        DateTimeOffset? issuedAt = null) =>
        Prepare(subscription, lifetime, payload, contentType, issuedAt);

    /// <summary>Prepares a bodyless event expiring at the supplied time.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        DateTimeOffset expiresAt) =>
        Prepare(subscription, expiresAt, payload: null, contentType: null);

    /// <summary>Prepares an event expiring at the supplied time and preserving raw bytes.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        DateTimeOffset expiresAt,
        byte[]? payload,
        string? contentType = null,
        DateTimeOffset? issuedAt = null)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        var issued = issuedAt ?? _clock();
        if (expiresAt <= issued)
            throw new ArgumentOutOfRangeException(nameof(expiresAt), "The event expiry must be after issue time.");
        return Build(subscription, issued, expiresAt, payload, contentType);
    }

    /// <summary>Prepares an event with raw payload bytes and an explicit expiry.</summary>
    public PreparedEventDelivery Prepare(
        ResourceSubscription subscription,
        byte[]? payload,
        DateTimeOffset expiresAt,
        string? contentType = null,
        DateTimeOffset? issuedAt = null) =>
        Prepare(subscription, expiresAt, payload, contentType, issuedAt);

    /// <summary>Alias for preparing an event with a lifetime.</summary>
    public PreparedEventDelivery PrepareEvent(
        ResourceSubscription subscription,
        TimeSpan lifetime,
        byte[]? payload = null,
        string? contentType = null,
        DateTimeOffset? issuedAt = null) =>
        Prepare(subscription, lifetime, payload, contentType, issuedAt);

    /// <summary>
    /// Sends a prepared event. The endpoint and HTTP signature are resolved
    /// afresh for every call, while the token and body remain byte-identical.
    /// </summary>
    public async Task<EventDeliveryResult> SendAsync(
        PreparedEventDelivery prepared,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var endpoint = await _endpointResolver.ResolveAsync(
            GetAgentProviderIssuer(prepared), cancellationToken).ConfigureAwait(false);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        if (prepared.HasPayload)
        {
            request.Content = new ByteArrayContent(prepared.Payload.ToArray());
            request.Content.Headers.TryAddWithoutValidation(
                "Content-Type", prepared.ContentType!);
        }

        var signer = new EventsRequestSigner(
            _resourceKey,
            () => prepared.CompactToken,
            _clock);
        if (prepared.HasPayload)
            signer.SignEvent(request);
        else
            signer.SignBodyless(request);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body;
        try
        {
            body = await EventsResponseBody.ReadUtf8Async(
                response.Content,
                cancellationToken: cancellationToken).ConfigureAwait(false) ?? string.Empty;
        }
        catch (EventsResponseBodyTooLargeException ex)
        {
            throw new EventDeliveryProtocolException(
                ex.Message,
                response.StatusCode,
                innerException: ex);
        }
        return ParseResponse(response.StatusCode, body);
    }

    private PreparedEventDelivery Build(
        ResourceSubscription subscription,
        DateTimeOffset issuedAt,
        DateTimeOffset requestedExpiry,
        byte[]? payload,
        string? contentType)
    {
        if (requestedExpiry > subscription.ExpiresAt)
            throw new ArgumentOutOfRangeException(
                nameof(requestedExpiry), "An event cannot outlive its subscription.");

        var bytes = payload is null ? Array.Empty<byte>() : (byte[])payload.Clone();
        if (bytes.Length != 0 && contentType is null)
            contentType = AAuthEventsConstants.JsonMediaType;
        var lifetime = requestedExpiry - issuedAt;
        var artifact = new EventTokenBuilder
        {
            Issuer = subscription.ResourceAudience,
            Audience = subscription.AgentSubject,
            Eid = subscription.Eid,
            KeyId = _resourceKeyId,
            Key = _resourceKey,
            IssuedAt = issuedAt,
            Lifetime = lifetime,
        }.Build();
        var expiry = DateTimeOffset.FromUnixTimeSeconds((issuedAt + lifetime).ToUnixTimeSeconds());
        return new PreparedEventDelivery(
            artifact.CompactToken,
            artifact.Jti,
            subscription.ApIssuer,
            expiry,
            bytes,
            contentType);
    }

    private string GetAgentProviderIssuer(PreparedEventDelivery prepared)
    {
        // The AP issuer is a subscription fact, not an event-token claim.
        // Keep it on the prepared object without exposing mutable state.
        return prepared.ApIssuer
            ?? throw new InvalidOperationException("Prepared delivery has no AP issuer.");
    }

    private static EventDeliveryResult ParseResponse(HttpStatusCode statusCode, string body)
    {
        if (statusCode == HttpStatusCode.Accepted)
        {
            if (string.IsNullOrWhiteSpace(body))
                return EventDeliveryResult.AcceptedResult();
            try
            {
                using var document = JsonDocument.Parse(body);
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                    throw new FormatException("A 202 response must contain an object.");
                var root = document.RootElement;
                if (!root.EnumerateObject().Any())
                    return EventDeliveryResult.AcceptedResult(responseBody: body);
                if (root.EnumerateObject().Count() != 1 ||
                    !root.TryGetProperty(AAuthEventsConstants.RemainingUsesProperty, out var remaining) ||
                    remaining.ValueKind != JsonValueKind.Number ||
                    !remaining.TryGetInt64(out var count) ||
                    count < 0)
                    throw new FormatException("A 202 response must contain only a non-negative remaining_uses integer.");
                return EventDeliveryResult.AcceptedResult(count, body);
            }
            catch (JsonException ex)
            {
                throw new EventDeliveryProtocolException(
                    "The 202 response is malformed JSON.", statusCode, body, ex);
            }
            catch (FormatException ex)
            {
                throw new EventDeliveryProtocolException(ex.Message, statusCode, body, ex);
            }
        }

        if ((int)statusCode == 429)
        {
            ValidateErrorBody(statusCode, body);
            return EventDeliveryResult.ExhaustedResult(body);
        }

        var outcome = statusCode switch
        {
            HttpStatusCode.BadRequest => EventDeliveryOutcome.BadRequest,
            HttpStatusCode.Unauthorized => EventDeliveryOutcome.Unauthorized,
            HttpStatusCode.Forbidden => EventDeliveryOutcome.Forbidden,
            HttpStatusCode.NotFound => EventDeliveryOutcome.NotFound,
            _ => EventDeliveryOutcome.Error,
        };
        ValidateErrorBody(statusCode, body);
        return new EventDeliveryResult(statusCode, outcome, ResponseBody: body);
    }

    private static void ValidateErrorBody(HttpStatusCode statusCode, string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return;
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new FormatException("An Events error response must contain a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new EventDeliveryProtocolException(
                "The Events error response is malformed JSON.", statusCode, body, ex);
        }
        catch (FormatException ex)
        {
            throw new EventDeliveryProtocolException(ex.Message, statusCode, body, ex);
        }
    }

    private static IAAuthKey ValidateKey(IAAuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!key.HasPrivateKey)
            throw new ArgumentException("The resource key must include a private component.", nameof(key));
        if (key.Algorithm is not ("EdDSA" or "ES256"))
            throw new ArgumentException("The resource key algorithm must be EdDSA or ES256.", nameof(key));
        return key;
    }
}
