using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Events.Resource;

namespace Bookings.Events;

/// <summary>
/// Sample-only in-memory waitlist tickets and subscriptions.
/// This is intentionally not a production durability implementation.
/// </summary>
public sealed class BookingsEventSubscriptions : IAAuthSubscriptionRegistrationHandler
{
    public const string SlotAvailable = "slot.available";

    private readonly object _gate = new();
    private readonly Dictionary<string, Ticket> _tickets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _usedTickets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, StoredSubscription> _subscriptions = new(StringComparer.Ordinal);
    private readonly TimeSpan _ticketLifetime;
    private readonly TimeSpan _subscriptionLifetime;
    private readonly Func<DateTimeOffset> _clock;

    public BookingsEventSubscriptions(
        TimeSpan ticketLifetime,
        TimeSpan subscriptionLifetime,
        Func<DateTimeOffset>? clock = null)
    {
        if (ticketLifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ticketLifetime));
        if (subscriptionLifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(subscriptionLifetime));
        _ticketLifetime = ticketLifetime;
        _subscriptionLifetime = subscriptionLifetime;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public IssuedTicket IssueTicket(string agentId, string context)
    {
        if (string.IsNullOrWhiteSpace(agentId)) throw new ArgumentException("An agent id is required.", nameof(agentId));
        if (string.IsNullOrWhiteSpace(context)) throw new ArgumentException("A ticket context is required.", nameof(context));

        lock (_gate)
        {
            var now = _clock();
            Cleanup(now);
            string value;
            Span<byte> bytes = stackalloc byte[18];
            do
            {
                RandomNumberGenerator.Fill(bytes);
                value = Convert.ToBase64String(bytes)
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');
            } while (_tickets.ContainsKey(value) || _usedTickets.ContainsKey(value));

            var expiresAt = now + _ticketLifetime;
            _tickets.Add(value, new Ticket(agentId, context, expiresAt));
            return new IssuedTicket(value, expiresAt);
        }
    }

    public bool TryGet(string eid, out StoredSubscription subscription)
    {
        lock (_gate)
        {
            Cleanup(_clock());
            return _subscriptions.TryGetValue(eid, out subscription!);
        }
    }

    public bool Remove(string eid)
    {
        lock (_gate)
            return _subscriptions.Remove(eid);
    }

    public ValueTask<SubscriptionRegistrationResult> RegisterAsync(
        SubscriptionEndpointContext endpoint,
        VerifiedSubscriptionRegistration registration,
        SignatureUnboundRegistrationBody? preferences,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(registration);

        if (preferences is not null)
        {
            if (!preferences.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
                return ValueTask.FromResult(SubscriptionRegistrationResult.BadRequest(
                    "The waitlist registration body must use application/json."));
            if (!HasOnlySlotAvailable(preferences.GetUtf8Text()))
                return ValueTask.FromResult(SubscriptionRegistrationResult.BadRequest(
                    "The registration body cannot widen or duplicate event types."));
        }

        var ticketValue = endpoint.Ticket;
        if (string.IsNullOrWhiteSpace(ticketValue))
            return ValueTask.FromResult(SubscriptionRegistrationResult.BadRequest("A waitlist ticket is required."));

        lock (_gate)
        {
            var now = _clock();
            Cleanup(now);

            if (_usedTickets.ContainsKey(ticketValue))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Conflict("The waitlist ticket was already used."));
            if (!_tickets.TryGetValue(ticketValue, out var ticket))
                return ValueTask.FromResult(SubscriptionRegistrationResult.NotFound("The waitlist ticket is unknown or expired."));
            if (!string.Equals(ticket.AgentId, registration.AgentSubject, StringComparison.Ordinal))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Forbidden("The ticket is bound to another agent."));
            if (!string.Equals(ticket.Context, endpoint.Descriptor.Name, StringComparison.Ordinal))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Forbidden("The ticket context does not match this channel."));
            if (endpoint.Descriptor.ResourceAudience is not null &&
                !string.Equals(endpoint.Descriptor.ResourceAudience, registration.ResourceAudience, StringComparison.Ordinal))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Forbidden("The token audience does not match this resource."));
            if (_subscriptions.ContainsKey(registration.Eid))
                return ValueTask.FromResult(SubscriptionRegistrationResult.Conflict("The event id is already registered."));

            var expiresAt = now + _subscriptionLifetime;
            if (expiresAt <= registration.IssuedAt)
                expiresAt = registration.IssuedAt.AddSeconds(1);

            ResourceSubscription stored;
            try
            {
                stored = ResourceSubscription.FromRegistration(registration, expiresAt);
            }
            catch (ArgumentException exception)
            {
                return ValueTask.FromResult(SubscriptionRegistrationResult.BadRequest(exception.Message));
            }

            _subscriptions.Add(registration.Eid, new StoredSubscription(stored, SlotAvailable, expiresAt));
            _tickets.Remove(ticketValue);
            _usedTickets[ticketValue] = ticket.ExpiresAt;
            return ValueTask.FromResult(SubscriptionRegistrationResult.Accepted([SlotAvailable]));
        }
    }

    private void Cleanup(DateTimeOffset now)
    {
        foreach (var pair in _tickets.Where(pair => pair.Value.ExpiresAt <= now).ToArray())
            _tickets.Remove(pair.Key);
        foreach (var pair in _usedTickets.Where(pair => pair.Value <= now).ToArray())
            _usedTickets.Remove(pair.Key);
        foreach (var pair in _subscriptions.Where(pair => pair.Value.ExpiresAt <= now).ToArray())
            _subscriptions.Remove(pair.Key);
    }

    private static bool HasOnlySlotAvailable(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("event_types", out var eventTypes) ||
                eventTypes.ValueKind != JsonValueKind.Array)
                return false;
            var values = eventTypes.EnumerateArray().ToArray();
            return values.Length == 1 &&
                   values[0].ValueKind == JsonValueKind.String &&
                   string.Equals(values[0].GetString(), SlotAvailable, StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private sealed record Ticket(string AgentId, string Context, DateTimeOffset ExpiresAt);
}

public sealed record IssuedTicket(string Value, DateTimeOffset ExpiresAt)
{
    public string SubscribeUrl(string resourceUrl) =>
        $"{resourceUrl.TrimEnd('/')}/waitlist/subscriptions/{Uri.EscapeDataString(Value)}";
}

public sealed record StoredSubscription(
    ResourceSubscription Subscription,
    string EventType,
    DateTimeOffset ExpiresAt);
