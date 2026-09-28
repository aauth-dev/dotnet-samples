# Mission Governance Clients

> [Mission Lifecycle](https://explorer.aauth.dev/missions/lifecycle)

## Overview

The mission lifecycle is driven by four agent-side clients that talk to the
Person Server's governance endpoints (§PS Governance Endpoints):

- `MissionClient` — propose a mission, record updates, and propose completion at
  the PS's `mission_endpoint`.
- `PermissionClient` — ask whether a local action (a tool) is allowed.
- `AuditClient` — report actions the agent has performed.
- `InteractionClient` — reach the user to relay an interaction or payment, or ask a question.

`AAuthGovernanceClient` bundles all four over a single signed channel. Every
governance request is signed with the agent identity, so the supplied
`HttpClient` must be wired with an `AAuthSigningHandler` carrying the agent
token. The easiest way to get a correctly wired client is
`AAuthClientBuilder.BuildGovernance()`.

For the mission model itself (the blob, `s256`, and how `mission_s256` flows
through person, resource, and auth tokens), see
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
that auto-threads the mission's `s256` (as `mission_s256`) and PS into every later call.

## Proposing a mission

The agent sends a Markdown `Description` of its intent plus the tools it wants
pre-approved. The PS may approve all tools, a subset, or none, and may run a
[clarification chat](clarification-chat.md) before approving. `ProposeMissionAsync`
returns a **session** scoped to the approved mission:

```csharp
var proposal = new MissionProposal("Plan a weekend trip to Seattle for four.")
{
    Tools = new[]
    {
        new MissionTool("calendar.read", "Check the user's weekend schedule."),
        new MissionTool("add_to_calendar", "Add the itinerary to the calendar."),
    },
};

MissionSession session = await governance.ProposeMissionAsync(
    proposal,
    new GovernanceOptions
    {
        OnClarificationRequired = async (requirement, ct) =>
            ClarificationResponse.Respond("This weekend, leaving Friday evening, four people."),
    });

Mission mission = session.Mission;
// mission.ApprovedTools may be a subset of what was proposed.
Console.WriteLine($"Mission {mission.S256} approved by {mission.PersonServer}.");
```

The PS answers with an approval envelope `{ s256, mission, capabilities?,
person_tokens? }`. `ProposeMissionAsync` decodes the base64url `mission` blob,
keeps its bytes verbatim, and verifies `s256` against them before returning; a
malformed envelope or a mismatch throws `InvalidOperationException`. If the
proposal named `Resources`, `mission.PersonTokens` holds any person tokens the PS
issued with the approval.

## Requesting permission for a tool

Tools are the actions the agent runs itself. Call it on the session: when the
action matches a pre-approved tool the call resolves locally without a PS
round-trip; otherwise it goes to the PS, which may grant, deny, or prompt the
user (§Permission Endpoint).

```csharp
PermissionResult result = await session.RequestPermissionAsync(
    new MissionAction("add_to_calendar"),
    description: "Add the flight and hotel to the user's calendar.");

if (result.IsGranted)
{
    // Pre-approved tool → granted locally with reason
    // "Pre-approved tool on the active mission."
    AddToCalendar();
}
else
{
    Console.WriteLine($"Denied: {result.Reason}");
}
```

The action is a `MissionAction` POCO — construct it with `new MissionAction("add_to_calendar")`
(or `tool.ToAction()` from a `MissionTool`). For an action not on the mission, the PS evaluates
it against the mission log and may prompt the user. Supply `OnInteractionRequired`
/ `OnClarificationRequired` via `GovernanceOptions` to participate in any deferral.

```csharp
PermissionResult outcome = await session.RequestPermissionAsync(
    new MissionAction("cancel_booking"),
    description: "Cancel the stale hotel hold the user mentioned.",
    parameters: new JsonObject { ["bookingId"] = "htl-old" });
```

## Recording an audit entry

Auditing happens after the fact and always requires a mission. It is
fire-and-forget — the PS acknowledges with `201 Created`. A terminated mission
surfaces as `AAuthMissionTerminatedException` (see
[Error Handling](error-handling.md#mission-termination)).

```csharp
await session.RecordAuditAsync(
    new MissionAction("add_to_calendar"),
    description: "Added the flight and hotel to the user's calendar.",
    result: new JsonObject { ["items"] = 2 });
```

## Reaching the user

The interaction endpoint is how the agent reaches the user through the PS:
relay a resource interaction it cannot satisfy itself, forward a payment, or ask a
question. Each request type resolves to a typed `InteractionResult`. Mission
updates and completion are not interactions: they are POSTed to the mission
itself at `{mission_endpoint}/{s256}` (§Mission Update, §Mission Completion).

```csharp
// Ask the user a clarifying question mid-mission.
string? answer = await session.AskQuestionAsync("Window seat or aisle?");

// Relay a resource interaction (e.g. a payment-style confirmation URL + code).
await session.RelayInteractionAsync(
    url: "https://resource.example/confirm/abc",
    code: "4821",
    description: "Confirm the booking.");

// Record a change in the work; returns the accepted update's s256. The mission is unchanged.
string updateS256 = await session.UpdateAsync("The hotel is full; booking a comparable one nearby.");

// Propose completion; true when the user accepted and the PS terminated the mission.
bool done = await session.ProposeCompletionAsync(
    "Booked the Friday-evening flight and a hotel for four, and added them to the calendar.");
```

`question` results fill `InteractionResult.Answer`; `interaction`/`payment`
resolve once the user completes. `ProposeCompletionAsync` returns `false` when
the person answered with follow-up questions and the mission stays active.

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
