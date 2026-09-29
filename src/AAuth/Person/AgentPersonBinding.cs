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

    /// <summary>The inventory key of the binding between <paramref name="agentIssuer"/>'s agent <paramref name="agentId"/> and its person.</summary>
    public static TokenKey Key(string personServer, string agentIssuer, string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personServer);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        return new TokenKey(personServer, "agent-person-binding " + agentIssuer + " " + agentId);
    }

    /// <summary>
    /// Revoke the binding in the PS's token inventory (the <see cref="IJtiStore"/> the PS was mapped with;
    /// register it in DI to share it with the host).
    /// </summary>
    public static Task RevokeAsync(IJtiStore inventory, string personServer, string agentIssuer, string agentId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        return inventory.RevokeAsync(Key(personServer, agentIssuer, agentId), ExpiresAt, cancellationToken);
    }

    internal static TokenRegistration Registration(string personServer, string agentIssuer, string agentId)
        => new(Key(personServer, agentIssuer, agentId), ExpiresAt);
}
