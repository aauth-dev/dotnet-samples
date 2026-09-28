using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Server.Governance;

/// <summary>
/// The approved mission and verified agent token a PS issues the approval's
/// <c>person_tokens</c> for (§Mission Approval).
/// </summary>
public sealed record MissionPersonTokenRequest
{
    /// <summary>The PS the mission was approved at; only that PS issues for it.</summary>
    public required string PersonServer { get; init; }

    /// <summary>The agent the mission was approved for (the agent token's <c>sub</c>).</summary>
    public required string AgentId { get; init; }

    /// <summary>The agent token's <c>cnf.jwk</c>; each person token binds it.</summary>
    public required IAAuthKey ConfirmationKey { get; init; }

    /// <summary>The agent token's <c>exp</c>; no person token outlives it.</summary>
    public required DateTimeOffset AgentTokenExpiresAt { get; init; }

    /// <summary>The verified agent token's inventory entries; each token is recorded as their grant so revoking them cascades.</summary>
    public required IReadOnlyList<TokenRegistration> SourceTokens { get; init; }

    /// <summary>The approved mission's <c>s256</c>, carried as each token's <c>mission_s256</c>.</summary>
    public required string MissionS256 { get; init; }

    /// <summary>The mission's <c>expires_at</c>, if any; no person token outlives it.</summary>
    public DateTimeOffset? MissionExpiresAt { get; init; }

    /// <summary>The approved resources (<c>approved_resources</c>) to issue for.</summary>
    public required IReadOnlyList<string> Resources { get; init; }
}

/// <summary>
/// Issues the person tokens a mission approval returns (§Mission Approval
/// <c>person_tokens</c>). <c>AddAAuthGovernance</c> registers a default that
/// <c>MapAAuthPersonServer</c> backs with the PS's own person-token minting;
/// without a PS it issues nothing and approvals omit <c>person_tokens</c>.
/// </summary>
public interface IMissionPersonTokenIssuer
{
    /// <summary>
    /// Issue a person token for each resource the PS agrees to, keyed by resource.
    /// A resource the PS declines is omitted.
    /// </summary>
    Task<IReadOnlyDictionary<string, string>> IssueAsync(MissionPersonTokenRequest request, CancellationToken ct = default);
}

// The AddAAuthGovernance default: MapAAuthPersonServer attaches the PS minting.
internal sealed class AttachableMissionPersonTokenIssuer : IMissionPersonTokenIssuer
{
    private static readonly IReadOnlyDictionary<string, string> None = new Dictionary<string, string>();

    internal Func<MissionPersonTokenRequest, CancellationToken, Task<IReadOnlyDictionary<string, string>>>? Issue { get; set; }

    public Task<IReadOnlyDictionary<string, string>> IssueAsync(MissionPersonTokenRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Issue?.Invoke(request, ct) ?? Task.FromResult(None);
    }
}
