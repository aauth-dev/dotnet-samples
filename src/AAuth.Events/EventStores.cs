namespace AAuth.Events;

public sealed record ProviderSubscription(string Eid, string Agent, string Resource,
    DateTimeOffset ExpiresAt, long? MaxUses);
public sealed record EventEnvelope(string Token, string Eid, string Issuer, string Agent,
    DateTimeOffset ExpiresAt, byte[] Body);
public sealed record EventAcceptance(int StatusCode, long? RemainingUses = null);
public sealed record PendingEvent(string Receipt, EventEnvelope Event);

public interface IAgentProviderEventStore
{
    void Create(ProviderSubscription subscription);
    EventAcceptance Accept(EventEnvelope envelope, DateTimeOffset now);
    IReadOnlyList<PendingEvent> Pending(string agent, int limit = 100, string? after = null);
    bool Acknowledge(string agent, string receipt);
}

public sealed record SubscriptionTicket(string Ticket, string KeyThumbprint, string Operation,
    string? Account, string State, DateTimeOffset ExpiresAt);
public sealed record ResourceSubscription(string Eid, string Provider, string Agent,
    string Operation, string? Account, string State, DateTimeOffset ExpiresAt, string? KeyThumbprint = null);
public sealed record RegistrationResult(int StatusCode, ResourceSubscription? Subscription = null);

public interface IResourceEventStore
{
    void SetState(string operation, string? account, string state);
    void IssueTicket(SubscriptionTicket ticket);
    RegistrationResult Register(ResourceSubscription subscription, string? ticket, DateTimeOffset now);
    ResourceSubscription? Find(string provider, string eid, DateTimeOffset now);
    void Complete(string provider, string eid);
}

public sealed record AgentEventContext(string Eid, string Resource, string Agent, string Context);
public sealed record ProcessedEvent(AgentEventContext Context, EventEnvelope Event);

public interface IAgentEventStore
{
    void Remember(AgentEventContext context);
    AgentEventContext? FindContext(string eid);
    bool RecordOnce(ProcessedEvent received, DateTimeOffset now);
    IReadOnlyList<ProcessedEvent> ReadEvents(string agent);
}