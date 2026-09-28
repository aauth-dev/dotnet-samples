using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>
/// A mission-scoped facade over an <see cref="AAuthGovernanceClient"/> bound to a
/// Person Server. It wraps the approved <see cref="Mission"/> and auto-threads the
/// mission claim (<c>{approver, s256}</c>) and the bound PS URL into every
/// permission, audit, and interaction call (§Permission Endpoint, §Audit Endpoint,
/// §Interaction Endpoint), so callers never re-supply them.
/// </summary>
/// <remarks>
/// Obtain a session from <see cref="AAuthGovernanceClient.ProposeMissionAsync"/>.
/// The session is the agent's handle for the lifetime of one mission.
/// </remarks>
public sealed class MissionSession
{
    private readonly AAuthGovernanceClient _governance;
    private readonly string _personServer;
    private readonly GovernanceOptions? _defaultOptions;

    internal MissionSession(
        AAuthGovernanceClient governance,
        string personServer,
        Mission mission,
        GovernanceOptions? defaultOptions)
    {
        _governance = governance ?? throw new ArgumentNullException(nameof(governance));
        _personServer = personServer ?? throw new ArgumentNullException(nameof(personServer));
        Mission = mission ?? throw new ArgumentNullException(nameof(mission));
        _defaultOptions = defaultOptions;
    }

    /// <summary>The approved mission this session is scoped to.</summary>
    public Mission Mission { get; }

    /// <summary>The Person Server this session's mission was approved by.</summary>
    public string PersonServer => _personServer;

    // The mission reference threaded into every governed request.
    private string Claim => Mission.S256;

    private GovernanceOptions? Options(GovernanceOptions? options)
        => (options ?? _defaultOptions)?.ForMission(Mission);

    /// <summary>
    /// Request permission for <paramref name="action"/> within this mission
    /// (§Permission Endpoint). Pre-approved tools short-circuit to a grant; any
    /// other action is evaluated by the PS. The mission claim and PS are injected.
    /// </summary>
    public Task<PermissionResult> RequestPermissionAsync(
        MissionAction action,
        string? description = null,
        JsonObject? parameters = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(() => _governance.Permission.RequestAsync(
            action, Mission, description, parameters,
            Options(options), cancellationToken));

    /// <summary>
    /// Record an action the agent performed within this mission (§Audit Endpoint).
    /// The mission claim and PS are injected.
    /// </summary>
    public Task RecordAuditAsync(
        MissionAction action,
        string? description = null,
        JsonObject? parameters = null,
        JsonObject? result = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(async () =>
        {
            await _governance.Audit.RecordAsync(
            new AuditRecord(Claim, action)
            {
                Description = description,
                Parameters = parameters,
                Result = result,
            },
            cancellationToken).ConfigureAwait(false);
            return true;
        });

    /// <summary>
    /// Ask the user a question within this mission and return the answer
    /// (§Interaction Endpoint). The mission claim and PS are injected.
    /// </summary>
    public Task<string?> AskQuestionAsync(
        string question,
        string? description = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(() => _governance.Interaction.AskQuestionAsync(
            question, description, Claim,
            Options(options), cancellationToken));

    /// <summary>
    /// Relay a resource interaction (URL + code) to the user (§Interaction
    /// Endpoint). The mission claim and PS are injected.
    /// </summary>
    public Task<InteractionResult> RelayInteractionAsync(
        string url,
        string code,
        string? description = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(() => _governance.Interaction.RelayInteractionAsync(
            url, code, description, Claim,
            Options(options), cancellationToken));

    /// <summary>
    /// Forward a payment approval (URL + code) to the user (§Interaction
    /// Endpoint). The mission claim and PS are injected.
    /// </summary>
    public Task<InteractionResult> RelayPaymentAsync(
        string url,
        string code,
        string? description = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(() => _governance.Interaction.RelayPaymentAsync(
            url, code, description, Claim,
            Options(options), cancellationToken));

    /// <summary>
    /// Record a change in the work (§Mission Update). Returns the accepted update's
    /// <c>s256</c>; the mission and its <c>mission_s256</c> are unchanged.
    /// </summary>
    public Task<string> UpdateAsync(
        string description,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => Mission.ExecuteAsync(() => _governance.Mission.UpdateAsync(
            Mission, description, Options(options), cancellationToken));

    /// <summary>
    /// Propose mission completion with a summary (§Mission Completion). Returns
    /// <see langword="true"/> when the user accepted and the PS terminated the
    /// mission.
    /// </summary>
    public async Task<bool> ProposeCompletionAsync(
        string summary,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var terminated = await Mission.ExecuteAsync(() => _governance.Mission.CompleteAsync(
            Mission, summary,
            Options(options), cancellationToken)).ConfigureAwait(false);
        if (terminated) Mission.Terminate();
        return terminated;
    }
}
