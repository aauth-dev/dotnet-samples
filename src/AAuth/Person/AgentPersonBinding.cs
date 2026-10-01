using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Server;

namespace AAuth.Person;

/// <summary>
/// The PS's agent-person binding (#agent-person-binding) as an entry in its token inventory.
/// Every token the PS issues directly to an agent is recorded as a grant of that agent's binding,
/// so revoking the binding makes those tokens revoked ancestors: a later request chaining one of
/// them as <c>upstream_token</c> is rejected with <c>revoked_upstream_token</c> (step 4 of upstream
/// token verification), and the agent itself is refused until it is bound again.
/// </summary>
public static class AgentPersonBinding
{
    // Bindings outlive any one agent token; a fixed far expiry keeps re-registration idempotent.
    internal static readonly DateTimeOffset ExpiresAt = new(9000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The inventory key of one binding generation between <paramref name="agentIssuer"/>'s agent <paramref name="agentId"/> and its person.</summary>
    public static TokenKey Key(string personServer, string agentIssuer, string agentId, long generation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personServer);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(generation);
        return new TokenKey(personServer, "agent-person-binding " + generation.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + " " + agentIssuer + " " + agentId);
    }

    /// <summary>
    /// Revoke the binding in the PS's token inventory (the <see cref="IJtiStore"/> the PS was mapped with;
    /// register it in DI to share it with the host).
    /// </summary>
    public static Task RevokeAsync(IJtiStore inventory, AgentPersonBindingRecord binding,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(binding);
        return inventory.RevokeAsync(binding.InventoryKey, ExpiresAt, cancellationToken);
    }

    /// <summary>
    /// Revoke the binding in both the token inventory and the binding store so a
    /// different person key can be enrolled only after the existing binding is
    /// revoked.
    /// </summary>
    public static async Task<AgentPersonBindingRecord?> RevokeAsync(IJtiStore inventory, IAgentPersonBindingStore bindingStore,
        string personServer, string agentIssuer, string agentId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(bindingStore);
        var binding = await bindingStore.RevokeAsync(personServer, agentIssuer, agentId, cancellationToken).ConfigureAwait(false);
        if (binding is not null)
            await RevokeAsync(inventory, binding, cancellationToken).ConfigureAwait(false);
        return binding;
    }

    internal static TokenRegistration Registration(AgentPersonBindingRecord binding)
        => new(binding.InventoryKey, ExpiresAt);
}
