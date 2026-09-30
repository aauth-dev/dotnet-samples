# Mission Governance (Server)

> [Mission Lifecycle](https://explorer.aauth.dev/missions/lifecycle)

## Overview

The Person Server is the contextual policy point for missions. It approves
missions, then evaluates every later request against the mission's
natural-language intent and the running mission log (§PS Governance Endpoints).
The SDK supplies the request/response parsing, the storage and log seams, and the
decision vocabulary; the PS owns the policy and the user channel.

This split is deliberate. A mission is a Markdown statement of intent, not a
machine-checkable rule set. The PS decides each request in context — the SDK
never tries to evaluate the mission for you. See
[Missions](../advanced/missions.md) for the agent-side model and how
`mission_s256` flows through tokens, and
[Mission Governance Clients](../advanced/mission-governance-clients.md) for the
calls the PS answers.

## Registering the seams

`AddAAuthGovernance` registers the storage defaults **and** conservative no-op
policy/user-channel defaults. Every seam is registered with `TryAdd`, so a PS can
register its own implementations (before or after the call) and keep the rest.
A Person Server registered with `AddAAuthPersonServer` can call `.WithGovernance()`
on its builder, which calls `AddAAuthGovernance` for you. Advertise the endpoints
with the options' `MissionPath`, `PermissionPath`, `AuditPath` and
`InteractionEndpointPath`.

```csharp
using Microsoft.Extensions.DependencyInjection;

builder.Services.AddAAuthGovernance(); // stores + no-op approver/decider/sink/relay

// Override the policy and user-channel seams with the PS's own:
builder.Services.AddSingleton<IMissionApprover>(missionApprover);
builder.Services.AddSingleton<IPermissionDecider>(permissionDecider);
builder.Services.AddSingleton<IAuditSink>(missionAuditSink);
builder.Services.AddSingleton<IInteractionRelay>(interactionRelay);
```

For a lightweight user channel you can supply the relay as a lambda instead of a
full `IInteractionRelay` class, via `AddAAuthInteractionRelay(...)` (backed by
`DelegateInteractionRelay`). It replaces any relay registered earlier, including
the no-op default:

```csharp
builder.Services.AddAAuthInteractionRelay(async (request, ct) =>
{
    // request.Type is question | interaction | payment; the mapper also relays
    // a mission completion proposal here with Type = Completion.
    var accepted = await askThroughUserChannel(request, ct);
    return new InteractionRelayResult { Accepted = accepted };
});
```

| Seam | Default (`AddAAuthGovernance`) | Who owns it |
|------|--------------------------------|-------------|
| `IMissionStore` | `InMemoryMissionStore` | SDK default; swap for durable storage |
| `IMissionLog` | `InMemoryMissionLog` | SDK default; swap for durable storage |
| `IMissionApprover` | `DefaultMissionApprover` | SDK default; PS supplies approval policy |
| `IPermissionDecider` | `DefaultPermissionDecider` (no-op) | PS supplies policy |
| `IAuditSink` | `DefaultAuditSink` (logs to the mission log) | PS supplies storage/alerting |
| `IInteractionRelay` | `DefaultInteractionRelay` (no user channel) | PS supplies the user channel |
| `IMissionTokenConsent` | `DefaultMissionTokenConsent` (hold for a user verdict) | PS supplies the out-of-scope mission **token** decision (`MapAAuthPersonServer`) |
| `IMissionPersonTokenIssuer` | Issues nothing until `MapAAuthPersonServer` attaches its person-token minting | SDK default; replace to mint approval `person_tokens` elsewhere |

By default a `Prompt` outcome is resolved synchronously (a permission denial / a
mission decline), since the mapper has no user channel. To opt into the deferred
`202`-poll consent flow (§Deferred Consent), also call `AddAAuthDeferredConsent()`,
which registers an in-memory `IDeferredConsentStore`; the mapper then parks the
request, answers `202 Accepted` with a poll `Location`, and resolves it once the
PS's browser consent page records the user's decision.

```csharp
builder.Services.AddAAuthGovernance();
builder.Services.AddAAuthDeferredConsent(); // Prompt → 202 + poll route
```

## Mapping the endpoints: `MapAAuthGovernance()`

`MapAAuthGovernance()` maps the mission, permission, audit, and interaction
endpoints (plus the deferred-consent poll route) onto the registered seams in one
call, mirroring `MapAAuthResource`. It also maps `POST {mission_endpoint}/{s256}`,
where the owning agent records an `update` or proposes `completion` (§Mission
Update, §Mission Completion). It parses each request with `GovernanceEndpoints`,
enforces the mission status rules, and delegates the decision to the seams:

```csharp
var app = builder.Build();

app.MapAAuthGovernance(); // /mission, /mission/{s256}, /permission, /audit, /mission-interaction + poll route

// Optional: override the default paths.
app.MapAAuthGovernance(o =>
{
    o.MissionPath = "/aauth/mission";
    o.PermissionPath = "/aauth/permission";
});
```

A mission-creation request requires a verified **agent token**; the mapper hands
the proposal to `IMissionApprover`, builds the mission blob with
`MissionApprovalBuilder`, persists the resulting `StoredMission`, and answers
with the approval envelope `{ s256, mission }` (the blob base64url-encoded).
When the proposal named `resources` and the same app maps `MapAAuthPersonServer`,
the envelope also carries `person_tokens`: for each approved resource the
`IIdentityClaimsAsserter` asserts (a `PersonTokenRequest` with `MissionS256`
set), the PS mints the same person token its `/person` endpoint would, bound to
the agent token's key and capped at its `exp` and the mission's `expires_at`.
Each is recorded as a grant of that agent token, so revoking the agent token
revokes them. A resource the asserter defers or denies is omitted; a deferred
approval mints them when the owning agent polls. Governance hosted without a PS
omits `person_tokens`.
A request naming a `mission_s256` that does not exist or belongs to another
agent is `404 mission_not_found` — the two cases are indistinguishable — and a
terminated or expired mission is `403 mission_terminated` (§Mission Endpoint
Errors). Reach for the manual mapping below only when an endpoint needs behavior
the seams do not express.

> **Carrier-type guard.** The governed endpoints require the request to carry the
> expected token type. When the wrong carrier is presented (e.g. an auth token
> where the mission flow expects an agent token), the mapper refuses with `403`
> `invalid_carrier_token` — an authorization failure on a valid signature, not a
> `401` authentication failure.

## Parsing requests by hand

When a PS maps its own endpoints, `GovernanceEndpoints` maps request bodies to the
shared DTOs, authorizes the mission reference, and emits the canonical mission
errors, so endpoints avoid hand-rolled parsing.

```csharp
using AAuth.Server.Governance;

app.MapPost("/aauth/permission", async (HttpContext ctx, IPermissionDecider decider,
    IMissionStore store, IMissionLog log) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    PermissionRequest request = GovernanceEndpoints.ParsePermission(body!);

    StoredMission? mission = request.MissionS256 is { } missionS256
        ? await store.GetAsync(missionS256)
        : null;

    // Agent token required; 404 mission_not_found for a missing or foreign
    // mission, 403 mission_terminated for a terminated or expired one.
    if (GovernanceEndpoints.Authorize(ctx, request.MissionS256, mission) is { } refused)
    {
        return refused;
    }

    var entries = mission is null
        ? Array.Empty<MissionLogEntry>()
        : await log.ReadAsync(mission.S256);

    var decision = await decider.DecideAsync(
        new PermissionDecisionContext(request, mission, entries));

    return decision.Outcome switch
    {
        PermissionOutcome.Granted => Results.Json(new { permission = "granted" }),
        PermissionOutcome.Denied => Results.Json(new { permission = "denied", reason = decision.Message }),
        _ => Results.Accepted(), // Prompt → defer to the user channel
    };
});
```

The parsers throw `FormatException` on a missing required field or a malformed
`mission_s256` (`ParsePermission` needs `action`, `ParseAudit` needs
`mission_s256` + `action`, `ParseInteraction` needs a `type` of `interaction`,
`payment`, or `question`, `ParseMissionProposal` needs `description`).

## Persisting missions: `IMissionStore`

A mission is stored as its verbatim blob bytes plus its lifecycle state, so the
`s256` stays verifiable. The second positional member names the approving PS
(the blob itself carries no PS).

```csharp
public sealed record StoredMission(string S256, string PersonServer, string Agent, ReadOnlyMemory<byte> Blob)
{
    public MissionState State { get; init; } = MissionState.Active;
    public DateTimeOffset? ExpiresAt { get; init; } // the blob's expires_at; terminated after it
}

public interface IMissionStore
{
    Task SaveAsync(StoredMission mission, CancellationToken ct = default);
    Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default);
    Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default); // e.g. on completion/revocation
}
```

## The mission log: `IMissionLog`

The log is the ordered record of what the agent did and what the PS decided. The
PS reads it to judge whether each new request is consistent with the mission, and
to resolve repeat requests silently via prior consent (§Mission Log, §Agent Token
Request).

```csharp
public enum MissionLogEntryKind { Token, Permission, Audit, Interaction, Update, Clarification }

public sealed record MissionLogEntry(string S256, MissionLogEntryKind Kind, DateTimeOffset Timestamp)
{
    public string? Account { get; init; }            // for token entries — prior-consent binding
    public string? AgentId { get; init; }            // for token entries — prior-consent binding
    public string? AgentKeyThumbprint { get; init; } // for token entries — prior-consent binding
    public string? Resource { get; init; } // for token entries — prior-consent lookup
    public string? Scope { get; init; }    // for token entries — prior-consent lookup
    public string? Action { get; init; }   // for permission/audit entries
    public bool? Granted { get; init; }     // governance decision
    public string? Detail { get; init; }    // justification or clarification text
}

public interface IMissionLog
{
    Task AppendAsync(MissionLogEntry entry, CancellationToken ct = default);
    Task<IReadOnlyList<MissionLogEntry>> ReadAsync(string s256, CancellationToken ct = default);
    Task<bool> HasPriorConsentAsync(string s256, string resource, string scope, CancellationToken ct = default,
        string? account = null, string? agentId = null, string? agentKeyThumbprint = null);
}
```

## The decision: three gates

When the agent requests an auth token or a permission, the PS reaches one of
three outcomes (§Permission Endpoint, §Auth Token Request). The SDK supplies the
outcome and reason enums; the PS supplies the policy in `IPermissionDecider`.

```csharp
public enum PermissionOutcome { Granted, Denied, Prompt }
public enum PermissionDecisionReason { InScope, PriorConsent, ApprovedTool, OutOfScope }

public sealed record PermissionDecision(
    PermissionOutcome Outcome,
    PermissionDecisionReason Reason,
    string? Message = null);
```

The gates, in order:

1. **Granted silently** when the request fits the mission — a pre-approved tool
   (`ApprovedTool`), a scope within the mission's intent (`InScope`), or a
   repeat of something the user already consented to (`PriorConsent`).
2. **Prompt the user** when the action is outside known scope (`OutOfScope`) —
   the PS defers and reaches the user before deciding.
3. **Denied** only on an explicit user denial, or refused with `403
   mission_terminated` once the mission is terminated.

```csharp
public sealed class MyPermissionDecider : IPermissionDecider
{
    private readonly IMissionLog _log;
    public MyPermissionDecider(IMissionLog log) => _log = log;

    public async Task<PermissionDecision> DecideAsync(
        PermissionDecisionContext context, CancellationToken ct = default)
    {
        var mission = context.Mission;
        if (mission is null)
        {
            return new PermissionDecision(PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope);
        }

        // Pre-approved tool → granted silently.
        var blob = Mission.FromBlob(mission.Blob.Span, mission.PersonServer);
        if (blob.ApprovedTools.Any(t => t.Name == context.Request.Action.Name))
        {
            return new PermissionDecision(PermissionOutcome.Granted, PermissionDecisionReason.ApprovedTool);
        }

        // Otherwise it is the PS's contextual judgement — here, prompt the user.
        return new PermissionDecision(
            PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope,
            "This action was not part of the approved mission.");
    }
}
```

## Audit and interaction sinks

The audit sink records what the agent reports and MAY alert the user or revoke
the mission; the interaction relay reaches the user for the PS.

Mission creation, mission-token and permission prompts need not be decided at
the per-request `/interaction` page. The PS hosts that URL, so it MAY complete
the interaction over a channel it already controls and consume the code there
([User Interaction](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#user-interaction),
v11 L1011). The sample
[consent dashboard](../../samples/MockPersonServer/README.md#consent-dashboard)
decides all three kinds, with an optional grouping by mission.

```csharp
public interface IAuditSink
{
    Task RecordAsync(AuditRecord record, CancellationToken ct = default);
}

public sealed record InteractionRelayResult
{
    public string? Answer { get; init; }  // for question
    public bool? Accepted { get; init; }  // for a relayed completion — true terminates the mission
    public bool Pending { get; init; }    // defer + let the agent poll
}

public interface IInteractionRelay
{
    Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default);
}
```

## Terminating a mission

When a mission is terminated, the PS moves it to `MissionState.Terminated` and
answers governed requests with the canonical error (§Mission Status Errors). The
agent's governance clients surface this as `AAuthMissionTerminatedException`.
A terminated mission never returns to active; the agent proposes a new one.

```csharp
await store.SetStateAsync(s256, MissionState.Terminated);

// Canonical 403 response body: { "error": "mission_terminated", "mission_status": "terminated" }
return GovernanceEndpoints.MissionTerminated();
```

## Further reading

- [Missions](../advanced/missions.md) — the mission model and `mission_s256`
- [Mission Governance Clients](../advanced/mission-governance-clients.md) — the agent calls the PS answers
- [Mission-Governed Access](../workflows/mission-governed-access.md) — end-to-end walkthrough
- [Token Issuance](token-issuance.md#mission-claims) — emitting `mission_s256` in tokens
- [Dependency Injection](../reference/dependency-injection.md#governance) — registering the seams
