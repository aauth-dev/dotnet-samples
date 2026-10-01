using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Person;

/// <summary>The PS-owned binding of one agent token identity to one person key.</summary>
public sealed record AgentPersonBindingContext(
    string PersonServer,
    string AgentIssuer,
    string AgentId,
    AAuthPersonKey PersonKey);

/// <summary>A live agent/person binding generation.</summary>
public sealed record AgentPersonBindingRecord(
    string PersonServer,
    string AgentIssuer,
    string AgentId,
    AAuthPersonKey PersonKey,
    long Generation)
{
    /// <summary>The revocation-inventory key for this binding generation.</summary>
    public AAuth.Server.TokenKey InventoryKey => AgentPersonBinding.Key(PersonServer, AgentIssuer, AgentId, Generation);
}

/// <summary>
/// Persists and atomically verifies the one-person invariant for
/// <c>(person server, agent_token.iss, agent_token.sub)</c>.
/// </summary>
public interface IAgentPersonBindingStore
{
    /// <summary>
    /// Atomically creates the binding when absent or verifies it matches the
    /// existing live binding. Returns <see langword="null"/> for a different
    /// person key; exceptions are treated by the host as fail-closed denials.
    /// </summary>
    Task<AgentPersonBindingRecord?> BindOrVerifyAsync(AgentPersonBindingContext binding, CancellationToken cancellationToken = default);

    /// <summary>Revokes the binding so a later request can enroll a new person.</summary>
    Task<AgentPersonBindingRecord?> RevokeAsync(string personServer, string agentIssuer, string agentId, CancellationToken cancellationToken = default);
}

/// <summary>In-memory agent/person binding store for development and tests.</summary>
public sealed class InMemoryAgentPersonBindingStore : IAgentPersonBindingStore
{
    private sealed record Entry(AAuthPersonKey PersonKey, long Generation, bool Revoked);

    private readonly ConcurrentDictionary<(string PersonServer, string AgentIssuer, string AgentId), Entry> _bindings = new();

    /// <inheritdoc />
    public Task<AgentPersonBindingRecord?> BindOrVerifyAsync(AgentPersonBindingContext binding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(binding);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.PersonServer);
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.AgentIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.AgentId);
        var key = (binding.PersonServer, binding.AgentIssuer, binding.AgentId);
        while (true)
        {
            if (!_bindings.TryGetValue(key, out var current))
            {
                var created = new Entry(binding.PersonKey, 1, Revoked: false);
                if (_bindings.TryAdd(key, created))
                    return Task.FromResult<AgentPersonBindingRecord?>(ToRecord(binding, created));
                continue;
            }
            if (!current.Revoked)
                return Task.FromResult(current.PersonKey == binding.PersonKey ? ToRecord(binding, current) : null);
            var replacement = new Entry(binding.PersonKey, checked(current.Generation + 1), Revoked: false);
            if (_bindings.TryUpdate(key, replacement, current))
                return Task.FromResult<AgentPersonBindingRecord?>(ToRecord(binding, replacement));
        }
    }

    /// <inheritdoc />
    public Task<AgentPersonBindingRecord?> RevokeAsync(string personServer, string agentIssuer, string agentId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = (personServer, agentIssuer, agentId);
        while (true)
        {
            if (!_bindings.TryGetValue(key, out var current))
                return Task.FromResult<AgentPersonBindingRecord?>(null);
            var record = new AgentPersonBindingRecord(personServer, agentIssuer, agentId, current.PersonKey, current.Generation);
            if (current.Revoked)
                return Task.FromResult<AgentPersonBindingRecord?>(record);
            if (_bindings.TryUpdate(key, current with { Revoked = true }, current))
                return Task.FromResult<AgentPersonBindingRecord?>(record);
        }
    }

    private static AgentPersonBindingRecord ToRecord(AgentPersonBindingContext binding, Entry entry)
        => new(binding.PersonServer, binding.AgentIssuer, binding.AgentId, entry.PersonKey, entry.Generation);
}
