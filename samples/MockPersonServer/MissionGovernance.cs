using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Server.Governance;
using AAuth.Tokens;

namespace MockPersonServer;

// -----------------------------------------------------------------------
// Mission governance support for the mock Person Server (§PS Governance
// Endpoints, §Agent Token Request, §Permission Endpoint, §Mission Log).
//
// The SDK ships the seams (IMissionStore / IMissionLog / IPermissionDecider /
// IAuditSink / IInteractionRelay) and the request parsers; the PS owns the
// policy and the user channel. These types are that PS policy for the demo.
//
// User decisions are SCRIPTED (option A): a test or the GuidedTour sets the
// next outcome on MissionConsentScript before the agent acts, so every
// Consent-Matrix row is reproducible without a real browser prompt. A
// production PS would replace this with an interactive consent screen.
// -----------------------------------------------------------------------

/// <summary>
/// Deterministic, scriptable stand-in for the user's consent decisions. The mock
/// PS consults it instead of prompting a human, so the mission flow is
/// reproducible end-to-end.
/// </summary>
public sealed class MissionConsentScript
{
    /// <summary>Whether the next mission proposal is approved (§Mission Creation).</summary>
    public bool ApproveMissionProposal { get; set; } = true;

    /// <summary>Whether an out-of-scope token request is approved when prompted (§Agent Token Request).</summary>
    public bool ApproveOutOfScopeToken { get; set; } = true;

    /// <summary>Whether a non-pre-approved permission is approved when prompted (§Permission Endpoint).</summary>
    public bool ApprovePermission { get; set; } = true;

    /// <summary>The answer the user gives to a question interaction (§Interaction Endpoint).</summary>
    public string QuestionAnswer { get; set; } = "Yes, go ahead.";

    /// <summary>Whether the user accepts a mission-completion proposal (§Interaction Endpoint).</summary>
    public bool AcceptCompletion { get; set; } = true;

    /// <summary>
    /// Whether an out-of-scope token request triggers a clarification chat
    /// before the user decision (§Clarification Chat). When set, the PS asks
    /// <see cref="ClarificationQuestion"/> before resolving via
    /// <see cref="ApproveOutOfScopeToken"/>.
    /// </summary>
    public bool RequireTokenClarification { get; set; }

    /// <summary>The question posed during a token clarification chat.</summary>
    public string ClarificationQuestion { get; set; } = "Why does this mission need this access?";

    /// <summary>
    /// When <see langword="true"/>, out-of-scope token and non-pre-approved
    /// permission prompts wait for a real decision made through the PS's
    /// browser interaction page (<c>/interaction?code=…</c>) instead of
    /// resolving immediately via <see cref="ApproveOutOfScopeToken"/> /
    /// <see cref="ApprovePermission"/>. The <c>MissionAgent</c> CLI sets this
    /// so a human approves each prompt in their browser; the deterministic
    /// integration test leaves it <see langword="false"/> (§User Interaction).
    /// </summary>
    public bool InteractiveBrowser { get; set; }

    // (resource|scope) pairs the user treats as within a new mission's intent.
    private readonly HashSet<string> _inScope = new(StringComparer.Ordinal);

    /// <summary>Declare a (resource, scope) as within the approved mission intent.</summary>
    public void SeedInScope(string resource, string scope) => _inScope.Add(ScopeKey(resource, scope));

    /// <summary>Snapshot the seeded in-scope set (captured per mission at approval).</summary>
    public IReadOnlySet<string> InScopeSnapshot() => new HashSet<string>(_inScope, StringComparer.Ordinal);

    /// <summary>Canonical (resource, scope) key used for in-scope and prior-consent lookups.</summary>
    public static string ScopeKey(string resource, string scope) => $"{resource.TrimEnd('/')}|{scope}";

    /// <summary>Render a (resource, scope) key as a human-readable "resource → scope" pair for consent screens.</summary>
    public static string FormatScopePair(string key)
    {
        var i = key.IndexOf('|');
        return i < 0 ? key : $"{key[..i]} → {key[(i + 1)..]}";
    }

    /// <summary>Reset every decision to its permissive default and clear the in-scope set.</summary>
    public void Reset()
    {
        ApproveMissionProposal = true;
        ApproveOutOfScopeToken = true;
        ApprovePermission = true;
        QuestionAnswer = "Yes, go ahead.";
        AcceptCompletion = true;
        RequireTokenClarification = false;
        ClarificationQuestion = "Why does this mission need this access?";
        InteractiveBrowser = false;
        _inScope.Clear();
    }
}

/// <summary>
/// Per-mission policy the PS snapshots at approval: the approved tool names and
/// the (resource, scope) set within the mission's intent. Used by the token and
/// permission gates to decide silent-vs-prompt.
/// </summary>
public sealed class MissionPolicyStore
{
    private readonly ConcurrentDictionary<string, MissionPolicy> _byS256 = new(StringComparer.Ordinal);

    /// <summary>Record the approved tools and in-scope (resource|scope) set for a mission.</summary>
    public void Record(string s256, string description, IReadOnlyList<MissionTool> approvedTools, IReadOnlySet<string> inScope)
        => _byS256[s256] = new MissionPolicy(
            description,
            new HashSet<string>(approvedTools.Select(t => t.Name), StringComparer.Ordinal),
            new HashSet<string>(inScope, StringComparer.Ordinal));

    /// <summary>The human-readable mission description captured at approval, if known.</summary>
    public string? Describe(string s256)
        => _byS256.TryGetValue(s256, out var policy) ? policy.Description : null;

    /// <summary>The approved tool names captured at approval (empty if the mission is unknown).</summary>
    public IReadOnlyCollection<string> ApprovedTools(string s256)
        => _byS256.TryGetValue(s256, out var policy) ? policy.Tools : Array.Empty<string>();

    /// <summary>The in-scope (resource, scope) pairs captured at approval, as "resource → scope" strings.</summary>
    public IReadOnlyCollection<string> InScopePairs(string s256)
        => _byS256.TryGetValue(s256, out var policy)
            ? policy.InScope.Select(MissionConsentScript.FormatScopePair).ToArray()
            : Array.Empty<string>();

    /// <summary>Whether <paramref name="action"/> is a pre-approved tool on the mission.</summary>
    public bool IsApprovedTool(string s256, string action)
        => _byS256.TryGetValue(s256, out var policy) && policy.Tools.Contains(action);

    /// <summary>Whether (<paramref name="resource"/>, <paramref name="scope"/>) is within the mission's intent.</summary>
    public bool IsInScope(string s256, string resource, string scope)
        => _byS256.TryGetValue(s256, out var policy)
            && policy.InScope.Contains(MissionConsentScript.ScopeKey(resource, scope));

    /// <summary>Forget a mission's policy (e.g. on termination).</summary>
    public void Remove(string s256) => _byS256.TryRemove(s256, out _);

    /// <summary>Clear all per-mission policy (demo reset).</summary>
    public void Clear() => _byS256.Clear();

    private sealed record MissionPolicy(string Description, HashSet<string> Tools, HashSet<string> InScope);
}

/// <summary>
/// The PS's permission policy (§Permission Endpoint): a pre-approved tool is
/// granted silently; any other action falls to the user, whose scripted decision
/// is reflected here. The reason is recorded so samples can show why each request
/// was silent or prompted.
/// </summary>
public sealed class SamplePermissionDecider : IPermissionDecider
{
    private readonly MissionPolicyStore _policy;

    public SamplePermissionDecider(MissionPolicyStore policy)
    {
        _policy = policy;
    }

    public Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, CancellationToken ct = default)
    {
        var action = context.Request.Action.Name;

        // §Permission Endpoint: a pre-approved tool resolves without prompting.
        if (context.Mission is not null && _policy.IsApprovedTool(context.Mission.S256, action))
        {
            return Task.FromResult(new PermissionDecision(
                PermissionOutcome.Granted, PermissionDecisionReason.ApprovedTool));
        }

        // Otherwise the user must be prompted; the endpoint parks the request
        // (202) and the scripted decision resolves it on the pending URL.
        return Task.FromResult(new PermissionDecision(
            PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope));
    }
}

/// <summary>
/// Records audit entries into the mission log (§Audit Endpoint). A production PS
/// would also run anomaly detection and could revoke the mission.
/// </summary>
public sealed class SampleAuditSink : IAuditSink
{
    private readonly IMissionLog _log;

    public SampleAuditSink(IMissionLog log) => _log = log;

    public Task RecordAsync(AuditRecord record, CancellationToken ct = default)
        => _log.AppendAsync(
            new MissionLogEntry(record.Mission.S256, MissionLogEntryKind.Audit, DateTimeOffset.UtcNow)
            {
                Action = record.Action.Name,
                Detail = record.Description,
            },
            ct);
}

/// <summary>
/// Reaches the "user" for interaction requests (§Interaction Endpoint). Answers
/// and completion acceptance come from the consent script so the flow is
/// deterministic.
/// </summary>
public sealed class SampleInteractionRelay : IInteractionRelay
{
    private readonly MissionConsentScript _script;

    public SampleInteractionRelay(MissionConsentScript script) => _script = script;

    public Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default)
        => Task.FromResult(request.Type switch
        {
            InteractionType.Question => new InteractionRelayResult { Answer = _script.QuestionAnswer },
            InteractionType.Completion => new InteractionRelayResult { Accepted = _script.AcceptCompletion },
            _ => new InteractionRelayResult { Pending = false },
        });
}

/// <summary>The kind of deferred request a pending entry represents.</summary>
public enum MissionPendingKind
{
    /// <summary>A mission proposal awaiting the user's approval (§Mission Creation).</summary>
    Mission,

    /// <summary>An out-of-scope token request awaiting the user decision.</summary>
    Token,

    /// <summary>A non-pre-approved permission request awaiting the user decision.</summary>
    Permission,
}

/// <summary>The lifecycle of a parked (202) mission-governance request.</summary>
public enum MissionPendingState
{
    /// <summary>A clarification chat is open; the poll returns 202 + clarification.</summary>
    AwaitingClarification,

    /// <summary>Ready for the user decision; the poll resolves it via the script.</summary>
    AwaitingDecision,

    /// <summary>The agent withdrew the request (DELETE); the poll returns 410 Gone.</summary>
    Cancelled,
}

/// <summary>
/// A parked mission-governance request (§User Interaction / §Clarification Chat).
/// Carries everything needed to resolve the request once the user decides, so the
/// agent's poll on the pending URL can complete it.
/// </summary>
public sealed class MissionPendingEntry
{
    /// <summary>Opaque single-use pending id (also the interaction code).</summary>
    public string Id { get; } = Guid.NewGuid().ToString("N");

    /// <summary>Whether this is a token or permission request.</summary>
    public required MissionPendingKind Kind { get; init; }

    /// <summary>The agent that made the request (token `sub`).</summary>
    public required string AgentId { get; init; }

    /// <summary>The mission this request belongs to.</summary>
    public required string S256 { get; init; }

    /// <summary>The mission approver (for re-emitting the mission claim).</summary>
    public required string Approver { get; init; }

    /// <summary>The requested resource (token requests).</summary>
    public string? Resource { get; init; }

    /// <summary>The requested scope (token requests).</summary>
    public string? Scope { get; init; }

    /// <summary>The requested action (permission requests).</summary>
    public string? Action { get; init; }

    /// <summary>The proposed mission awaiting approval (mission-creation requests).</summary>
    public MissionProposal? Proposal { get; init; }

    /// <summary>The agent's confirmation key, captured to mint the auth token.</summary>
    public IAAuthKey? ConfirmationKey { get; init; }

    /// <summary>Any upstream act claim to carry into the issued auth token.</summary>
    public JsonObject? UpstreamAct { get; init; }

    /// <summary>The clarification question (when started in clarification).</summary>
    public string? Question { get; init; }

    /// <summary>Current lifecycle state.</summary>
    public MissionPendingState State { get; set; }

    /// <summary>
    /// The browser decision when running in interactive mode: <see langword="null"/>
    /// while the user has not yet decided, <see langword="true"/> on approve,
    /// <see langword="false"/> on deny. Ignored in scripted mode.
    /// </summary>
    public bool? Decision { get; set; }

    /// <summary>The mission claim to embed in the issued auth token.</summary>
    public MissionClaim MissionClaim => new(Approver, S256);
}

/// <summary>In-memory store of parked mission-governance requests.</summary>
public sealed class MissionPendingStore
{
    private readonly ConcurrentDictionary<string, MissionPendingEntry> _entries = new(StringComparer.Ordinal);

    /// <summary>Park <paramref name="entry"/> and return it.</summary>
    public MissionPendingEntry Add(MissionPendingEntry entry)
    {
        _entries[entry.Id] = entry;
        return entry;
    }

    /// <summary>Look up a pending entry by id.</summary>
    public MissionPendingEntry? Get(string id)
        => _entries.TryGetValue(id, out var entry) ? entry : null;

    /// <summary>Remove a resolved pending entry.</summary>
    public void Remove(string id) => _entries.TryRemove(id, out _);

    /// <summary>Clear all pending entries (demo reset).</summary>
    public void Clear() => _entries.Clear();
}
