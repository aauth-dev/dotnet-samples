# Calendar — PS-Asserted (three-party) resource server

Aria's core user-data service. The **Calendar** holds the traveler's events, so
Aria must present a person-scoped **auth token** (issued by the user's Person
Server) to read or change them. This is the three-party flow: the resource
challenges an agent token with a resource token (`aud` = PS), the agent exchanges
it at the PS for an auth token, and the resource verifies that token's issuer via
JWKS.

> **Sample only — not part of the AAuth SDK.**

Port: `http://localhost:5001`. Trusts the Person Server at
`http://localhost:5100` (override via `AAuth:TrustedPersonServers`).

## Endpoints

| Path | Scope / role | Demonstrates | `accessMode` |
|------|--------------|--------------|--------------|
| `/` | _(index)_ | — | — |
| `/events` | `calendar.read` | three-party baseline read | `three-party` |
| `/events/write` | `calendar.write` | **step-up** scope (a second consent) | `three-party` |
| `/events/admin` | role `calendar.owner` | **RBAC** by a PS-asserted role | `three-party` |

`/events/admin` enforces a role the PS asserts in the auth token's `roles`
claim. If the PS issues a token **without** that role, the policy returns an
unrecoverable **403** — there is no automatic step-up re-challenge in this
sample. The mock PS asserts `calendar.owner` only for `aauth:demo@…` agents, so a
non-admin agent deliberately exercises the 403 path.

## Running

```bash
dotnet run --project samples/MockResourceServers/Calendar
```

## With AgentConsole (grant consent first)

```bash
# Baseline three-party (calendar.read) — the default jwt mode maps to /events
dotnet run --project samples/AgentConsole -- http://localhost:5001/events \
  --ap http://localhost:5301 --ps http://localhost:5100 --sub aauth:demo@ap.example

# Step-up scope (calendar.write)
dotnet run --project samples/AgentConsole -- http://localhost:5001/events/write \
  --ap http://localhost:5301 --ps http://localhost:5100 --sub aauth:demo@ap.example

# RBAC (role calendar.owner) — demo agent succeeds; a guest agent gets 403
dotnet run --project samples/AgentConsole -- http://localhost:5001/events/admin \
  --ap http://localhost:5301 --ps http://localhost:5100 --sub aauth:demo@ap.example
```

The Concierge's plain call chain also targets this server's `/events`
endpoint (`Agent → Concierge → Calendar`). See
[Mock Resource Servers](../README.md).
