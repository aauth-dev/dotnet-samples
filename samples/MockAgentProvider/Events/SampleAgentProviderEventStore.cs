using AAuth.Events.AgentProvider;

namespace MockAgentProvider.Events;

/// <summary>
/// Sample-only in-memory AP Events store. It is intentionally non-durable and
/// must not be used as a production implementation.
/// </summary>
public sealed class SampleAgentProviderEventStore : IAAuthAgentProviderEventStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, AgentProviderSubscription> _subscriptions =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, StoredReceipt> _acceptedByTokenHash =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, StoredReceipt> _pendingByReceiptId =
        new(StringComparer.Ordinal);

    public Task<bool> TryCreateSubscriptionAsync(
        AgentProviderSubscription subscription,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            // Sample-only warning: this lock gives the example atomic behavior,
            // but the state is lost when the process stops.
            if (_subscriptions.ContainsKey(subscription.Eid))
                return Task.FromResult(false);

            _subscriptions.Add(subscription.Eid, new AgentProviderSubscription(
                subscription.Eid,
                subscription.Agent,
                subscription.Resource,
                subscription.MaxUses,
                subscription.ExpiresAt));
            return Task.FromResult(true);
        }
    }

    public Task<EventAcceptanceResult> AcceptEventAsync(
        IncomingEvent incomingEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(incomingEvent);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var tokenHash = incomingEvent.TokenHashHex;
            if (_acceptedByTokenHash.TryGetValue(tokenHash, out var existing))
                return Task.FromResult(EventAcceptanceResult.AlreadyAccepted(existing.Event, existing.RemainingUses));

            var claims = incomingEvent.Claims;
            if (!_subscriptions.TryGetValue(claims.Eid, out var subscription))
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.UnknownSubscription));

            if (!string.Equals(claims.Issuer, subscription.Resource, StringComparison.Ordinal))
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongResource));
            if (!string.Equals(claims.Audience, subscription.Agent, StringComparison.Ordinal))
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.WrongAudience));

            var now = incomingEvent.ReceiptTime;
            if (subscription.Status == AgentProviderSubscriptionStatus.Revoked)
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.ExpiredSubscription));

            if (subscription.Status == AgentProviderSubscriptionStatus.Expired ||
                claims.ExpiresAt <= now ||
                subscription.ExpiresAt <= now)
            {
                subscription.Status = AgentProviderSubscriptionStatus.Expired;
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.ExpiredSubscription));
            }

            if (subscription.MaxUses is not null &&
                subscription.UseCount >= subscription.MaxUses.Value)
            {
                subscription.Status = AgentProviderSubscriptionStatus.Exhausted;
                return Task.FromResult(new EventAcceptanceResult(EventAcceptanceOutcome.Exhausted));
            }

            subscription.UseCount++;
            var remaining = subscription.MaxUses is null
                ? (long?)null
                : subscription.MaxUses.Value - subscription.UseCount;
            var stored = new StoredReceipt(incomingEvent, subscription.Agent, remaining);
            _acceptedByTokenHash.Add(tokenHash, stored);
            _pendingByReceiptId.Add(stored.ReceiptId, stored);
            if (remaining == 0)
                subscription.Status = AgentProviderSubscriptionStatus.Exhausted;

            return Task.FromResult(EventAcceptanceResult.Accepted(incomingEvent, remaining));
        }
    }

    /// <summary>
    /// Returns a defensive, non-destructive snapshot for the sample polling
    /// endpoint. This is not an AAuth Events transport contract.
    /// </summary>
    public Task<IReadOnlyList<SamplePendingReceipt>> ListPendingAsync(
        string agentId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(agentId))
            throw new ArgumentException("An agent id is required.", nameof(agentId));
        if (limit <= 0)
            throw new ArgumentOutOfRangeException(nameof(limit));
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var result = _pendingByReceiptId.Values
                .Where(receipt => string.Equals(receipt.AgentId, agentId, StringComparison.Ordinal))
                .OrderBy(receipt => receipt.Event.ReceiptTime)
                .ThenBy(receipt => receipt.ReceiptId, StringComparer.Ordinal)
                .Take(limit)
                .Select(receipt => receipt.ToPublic())
                .ToArray();
            return Task.FromResult<IReadOnlyList<SamplePendingReceipt>>(result);
        }
    }

    /// <summary>Atomically acknowledges only a receipt owned by the agent.</summary>
    public Task<bool> AcknowledgeAsync(
        string agentId,
        string receiptId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(agentId))
            throw new ArgumentException("An agent id is required.", nameof(agentId));
        if (string.IsNullOrWhiteSpace(receiptId))
            throw new ArgumentException("A receipt id is required.", nameof(receiptId));
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!_pendingByReceiptId.TryGetValue(receiptId, out var receipt) ||
                !string.Equals(receipt.AgentId, agentId, StringComparison.Ordinal))
                return Task.FromResult(false);

            _pendingByReceiptId.Remove(receiptId);
            return Task.FromResult(true);
        }
    }

    private sealed record StoredReceipt(
        IncomingEvent Event,
        string AgentId,
        long? RemainingUses)
    {
        public string ReceiptId => Event.TokenHashHex;

        public SamplePendingReceipt ToPublic() =>
            new(
                ReceiptId,
                Event.CompactToken,
                Event.RawPayloadBytes,
                Event.ContentType ?? "application/octet-stream",
                Event.ReceiptTime);
    }
}

/// <summary>Defensive snapshot returned by the sample-only pending inbox.</summary>
public sealed record SamplePendingReceipt(
    string ReceiptId,
    string EventToken,
    byte[] Payload,
    string ContentType,
    DateTimeOffset ReceivedAt)
{
    public byte[] PayloadBytes => Payload.ToArray();
}
