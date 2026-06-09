# Trips — mission-governed (three-party, mission-aware) resource server

Aria's trip-planning service. The **Trips** server is *mission-aware*: when the
agent sends a signed `AAuth-Mission` header, the resource token it issues carries
the mission object (`approver` + `s256`), so the agent's Person Server can govern
the exchange against the human-approved mission.

> **Sample only — not part of the AAuth SDK.**

Port: `http://localhost:5002`. Trusts the Person Server at
`http://localhost:5100`.

## Endpoints

| Path | Scope | Demonstrates | `accessMode` |
|------|-------|--------------|--------------|
| `/` | _(index)_ | — | — |
| `/trips` | `trips.read` | **in-mission** scope — granted silently when the mission's intent covers reading trips (gate 2) | `three-party` |
| `/trips/book` | `trips.book` | **out-of-mission** scope — falls outside the mission intent, so the PS **prompts** the user before issuing the auth token (gate 3) | `three-party` |

The contrast between `/trips` (silent) and `/trips/book` (prompt) is the whole
point: it shows how a mission's approved intent gates which exchanges are silent
versus which require fresh consent. The issued auth token echoes the `mission`
claim back, surfaced in the response so the demo can show the mission
round-tripping end to end.

## Running

```bash
dotnet run --project samples/MockResourceServers/Trips
```

This is the resource the [MissionAgent](../../MissionAgent/README.md) CLI drives,
and the downstream hop of the GuidedTour / SampleApp **mission call-chain**
(`Agent → Orchestrator → Trips`). See [Mock Resource Servers](../README.md).
