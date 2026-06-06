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

    // The mission claim threaded into every governed request.
    private MissionClaim Claim => new(Mission.Approver, Mission.S256);

    /// <summary>
    /// Request permission for <paramref name="action"/> within this mission
    /// (§Permission Endpoint). Pre-approved tools short-circuit to a grant; any
    /// other action is evaluated by the PS. The mission claim and PS are injected.
    /// </summary>
    public Task<PermissionResult> RequestPermissionAsync(
        string action,
        string? description = null,
        JsonObject? parameters = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => _governance.Permission.RequestAsync(
            _personServer, action, Mission, description, parameters,
            options ?? _defaultOptions, cancellationToken);

    /// <summary>
    /// Record an action the agent performed within this mission (§Audit Endpoint).
    /// The mission claim and PS are injected.
    /// </summary>
    public Task RecordAuditAsync(
        string action,
        string? description = null,
        JsonObject? parameters = null,
        JsonObject? result = null,
        CancellationToken cancellationToken = default)
        => _governance.Audit.RecordAsync(
            _personServer,
            new AuditRecord(Claim, action)
            {
                Description = description,
                Parameters = parameters,
                Result = result,
            },
            cancellationToken);

    /// <summary>
    /// Ask the user a question within this mission and return the answer
    /// (§Interaction Endpoint). The mission claim and PS are injected.
    /// </summary>
    public Task<string?> AskQuestionAsync(
        string question,
        string? description = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => _governance.Interaction.AskQuestionAsync(
            _personServer, question, description, Claim,
            options ?? _defaultOptions, cancellationToken);

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
        => _governance.Interaction.RelayInteractionAsync(
            _personServer, url, code, description, Claim,
            options ?? _defaultOptions, cancellationToken);

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
        => _governance.Interaction.RelayPaymentAsync(
            _personServer, url, code, description, Claim,
            options ?? _defaultOptions, cancellationToken);

    /// <summary>
    /// Propose mission completion with a summary (§Interaction Endpoint). Returns
    /// <see langword="true"/> when the user accepted and the PS terminated the
    /// mission. The mission claim and PS are injected.
    /// </summary>
    public Task<bool> ProposeCompletionAsync(
        string summary,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
        => _governance.Interaction.ProposeCompletionAsync(
            _personServer, summary, Claim,
            options ?? _defaultOptions, cancellationToken);
}
