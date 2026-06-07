# Mission Governance Clients

> [Mission Lifecycle](https://explorer.aauth.dev/missions/lifecycle)

## Overview

The mission lifecycle is driven by four agent-side clients that talk to the
Person Server's governance endpoints (§PS Governance Endpoints):

- `MissionClient` — propose a mission and receive the approved blob.
- `PermissionClient` — ask whether a local action (a tool) is allowed.
- `AuditClient` — report actions the agent has performed.
- `InteractionClient` — reach the user to relay an interaction, ask a question, or close out the mission.

`AAuthGovernanceClient` bundles all four over a single signed channel. Every
governance request is signed with the agent identity, so the supplied
`HttpClient` must be wired with an `AAuthSigningHandler` carrying the agent
token. The easiest way to get a correctly wired client is
`AAuthClientBuilder.BuildGovernance()`.

For the mission model itself (the blob, `s256`, the `AAuth-Mission` header), see
[Missions](missions.md). For the PS side of these endpoints, see
[Mission Governance (Server)](../server/mission-governance.md).

## Building the facade

The client is **bound to one Person Server**. The easiest way to build it is
`AAuthClientBuilder.BuildGovernance()`, which requires an explicit signing mode
and a configured PS:

```csharp
using AAuth.Agent.Governance;

// Requires an explicit signing mode AND a Person Server; BuildGovernance throws otherwise.
AAuthGovernanceClient governance = new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithPersonServer("https://ps.example")
    .BuildGovernance();
```

You can also construct it directly from an already-signed channel — the PS URL is
still required:

```csharp
var governance = new AAuthGovernanceClient(signedClient, metadataClient, "https://ps.example");
```

The four endpoint clients are exposed as bound properties
(`governance.Mission`, `.Permission`, `.Audit`, `.Interaction`) for direct use,
but the usual path is `ProposeMissionAsync`, which returns a `MissionSession`
that auto-threads the mission claim and PS into every later call.

## Proposing a mission

The agent sends a Markdown `Description` of its intent plus the tools it wants
pre-approved. The PS may approve all tools, a subset, or none, and may run a
[clarification chat](clarification-chat.md) before approving. `ProposeMissionAsync`
returns a **session** scoped to the approved mission:

```csharp
var proposal = new MissionProposal("Book a table for four near the office on Friday.")
{
    Tools = new[]
    {
        new MissionTool("calendar.read", "Check the user's Friday schedule."),
        new MissionTool("email.send", "Send the confirmation to the group."),
    },
};

MissionSession session = await governance.ProposeMissionAsync(
    proposal,
    new GovernanceOptions
    {
        OnClarificationRequired = async (requirement, ct) =>
            ClarificationResponse.Respond("Friday dinner, around 7pm, four people."),
    });

Mission mission = session.Mission;
// mission.ApprovedTools may be a subset of what was proposed.
Console.WriteLine($"Mission {mission.S256} approved by {mission.Approver}.");
```

`ProposeMissionAsync` stores the approval body verbatim, computes its `s256`, and
verifies it against the `AAuth-Mission` response header before returning. A
mismatch throws `InvalidOperationException`.

## Requesting permission for a tool

Tools are the actions the agent runs itself. Call it on the session: when the
action matches a pre-approved tool the call resolves locally without a PS
round-trip; otherwise it goes to the PS, which may grant, deny, or prompt the
user (§Permission Endpoint).

```csharp
PermissionResult result = await session.RequestPermissionAsync(
    "email.send",
    description: "Send the booking confirmation to the four guests.");

if (result.IsGranted)
{
    // Pre-approved tool → granted locally with reason
    // "Pre-approved tool on the active mission."
    SendEmail();
}
else
{
    Console.WriteLine($"Denied: {result.Reason}");
}
```

The action is a `MissionAction` POCO — construct it with `new MissionAction("email.send")`
(or `tool.ToAction()` from a `MissionTool`). For an action not on the mission, the PS evaluates
it against the mission log and may prompt the user. Supply `OnInteractionRequired`
/ `OnClarificationRequired` via `GovernanceOptions` to participate in any deferral.

```csharp
PermissionResult outcome = await session.RequestPermissionAsync(
    new MissionAction("files.delete"),
    description: "Remove the stale draft the user mentioned.",
    parameters: new JsonObject { ["path"] = "/drafts/old.md" });
```

## Recording an audit entry

Auditing happens after the fact and always requires a mission. It is
fire-and-forget — the PS acknowledges with `201 Created`. A terminated mission
surfaces as `AAuthMissionTerminatedException` (see
[Error Handling](error-handling.md#mission-termination)).

```csharp
await session.RecordAuditAsync(
    new MissionAction("email.send"),
    description: "Sent booking confirmation to 4 recipients.",
    result: new JsonObject { ["messageId"] = "msg-8842" });
```

## Reaching the user

The interaction endpoint is how the agent reaches the user through the PS:
relay a resource interaction it cannot satisfy itself, forward a payment, ask a
question, or propose mission completion. Each request type resolves to a typed
`InteractionResult`.

```csharp
// Ask the user a clarifying question mid-mission.
string? answer = await session.AskQuestionAsync("Window seat or booth?");

// Relay a resource interaction (e.g. a payment-style confirmation URL + code).
await session.RelayInteractionAsync(
    url: "https://resource.example/confirm/abc",
    code: "4821",
    description: "Confirm the reservation.");

// Propose completion; true when the user accepted and the PS terminated the mission.
bool done = await session.ProposeCompletionAsync(
    "Booked Table 12 for four at 7pm Friday and emailed the group.");
```

Each interaction call returns an `InteractionResult` whose populated fields depend
on the type: `question` fills `Answer`, `completion` fills `Terminated`, and
`interaction`/`payment` resolve once the user completes.

## A full lifecycle

```csharp
var governance = new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithPersonServer("https://ps.example")
    .BuildGovernance();

// 1. Propose → approve (returns a session scoped to the mission)
var session = await governance.ProposeMissionAsync(
    new MissionProposal("Tidy the user's reading list.")
    {
        Tools = new[] { new MissionTool("bookmarks.archive") },
    });

// 2. Permission for a pre-approved tool → granted silently
var perm = await session.RequestPermissionAsync(new MissionAction("bookmarks.archive"));

// 3. Do the work, then audit it
await session.RecordAuditAsync(
    new MissionAction("bookmarks.archive"),
    result: new JsonObject { ["archived"] = 12 });

// 4. Close the mission out
bool terminated = await session.ProposeCompletionAsync("Archived 12 stale bookmarks.");
```

## Further reading

- [Missions](missions.md) — the mission model and binding chain
- [Clarification Chat](clarification-chat.md) — answering PS follow-ups during approval
- [Mission Governance (Server)](../server/mission-governance.md) — the PS-side seams
- [Mission-Governed Access](../workflows/mission-governed-access.md) — end-to-end walkthrough
- [Dependency Injection](../reference/dependency-injection.md#governance) — registering the governance clients
