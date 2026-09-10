---
description: Enrolled agent CLI with JWT authorization and explicit generic signing demonstrations.
---

# Agent Console

A command-line AAuth agent. It enrols with an Agent Provider, signs requests
with RFC 9421, handles `401` challenges, and — when given a Person Server —
runs the three-party exchange to obtain an auth token.

## What it does

- Enrols (and caches) an agent key with the Agent Provider (`--ap`).
- Signs a `GET` to the target URL and prints the resource's JSON response.
- On a `401` challenge, follows the indicated flow for the chosen
  `--signing-mode`.
- With `--ps`, performs the three-party exchange: agent token → resource
  token → PS `POST /token` → auth token → retried request.
- With `--resource-managed`, performs the two-party flow: a `202` from the
  resource yields a consent URL to approve, then a poll returns an opaque
  `AAuth-Access` token that is replayed as `Authorization: AAuth`. No `--ps`.

## Run

```bash
dotnet run --project samples/AgentConsole -- <url> --ap <agent-provider-url> [options]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--ap <url>` | _(required)_ | Agent Provider URL (enrol + refresh endpoints) |
| `--sub <id>` | `aauth:demo@ap.example` | Local enrollment-cache label; the AP assigns the actual agent identity |
| `--ps <url>` | _(none)_ | Person Server URL — enables the three-party flow |
| `--resource-managed` | _(off)_ | Agent-JWT two-party authorization; no `--ps`; drives consent then replays opaque `AAuth-Access` |
| `--signing-mode <mode>` | `jwt` | `jwt` for AAuth; explicit `hwk`, `jwks`, `jkt-jwt` for generic signing demonstrations |
| `--prefer-wait <seconds>` | _(none)_ | Long-poll hint for deferred PS responses |
| `--upstream-token <jwt>` | _(none)_ | Upstream auth token for call-chaining scenarios |

## Signing-mode → path mapping

When the target URL has no path (or just `/`), AgentConsole appends the path
that routes to the matching verification pipeline. The pseudonymous and
agent-identity modes target the **Profile** server (port 5000); the default
three-party `jwt` mode targets the **Calendar** server (port 5001); the
`--resource-managed` flag targets the **Inbox** server (port 5004):

| `--signing-mode` | Appended path | Server endpoint |
|------------------|---------------|-----------------|
| `hwk` | `/pseudonymous` | Profile :5000 — Pseudonymous (signature only) |
| `jkt-jwt` | `/anchored` | Profile :5000 — Pseudonymous, key delegation |
| `jwks` | `/identified` | Profile :5000 - generic direct JWKS demonstration |
| `jwt` _(default)_ | `/events` | Calendar :5001 — Three-party baseline |
| `--resource-managed` _(flag)_ | `/messages` | Inbox :5004 — Resource-managed (two-party) |

To reach the elevated (`/events/write`), RBAC (`/events/admin`), or payment
(`/wallet/charge`) endpoints, pass the explicit path — these are not
auto-appended.

## Validated invocations

Against the running Profile (5000), Calendar (5001), Wallet (5003),
Inbox (5004), MockAgentProvider (5301), and MockPersonServer (5100):

```bash
# Pseudonymous — HTTP signature only (no PS)
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000/pseudonymous --ap http://localhost:5301 --signing-mode hwk

# Pseudonymous, key delegation via naming JWT
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000 --ap http://localhost:5301 --signing-mode jkt-jwt

# Generic identity - key verified via direct JWKS
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000 --ap http://localhost:5301 --signing-mode jwks

# Resource-managed (two-party) — opaque AAuth-Access token, no PS
# Prints a consent URL; approve it in the browser, then the read replays.
dotnet run --project samples/AgentConsole -- \
  http://localhost:5004 --ap http://localhost:5301 --resource-managed

# Three-party baseline — scope "calendar.read" (grant consent first)
dotnet run --project samples/AgentConsole -- \
  http://localhost:5001 --ap http://localhost:5301 --ps http://localhost:5100

# Three-party, elevated scope "calendar.write"
dotnet run --project samples/AgentConsole -- \
  http://localhost:5001/events/write --ap http://localhost:5301 \
  --ps http://localhost:5100 --signing-mode jwt

# Three-party, RBAC — PS asserts roles ["calendar.owner"], groups ["demo-users"]
dotnet run --project samples/AgentConsole -- \
  http://localhost:5001/events/admin --ap http://localhost:5301 \
  --ps http://localhost:5100 --signing-mode jwt

# Four-party payment — scope "wallet.charge" (Access Server requires the wallet.payer role)
dotnet run --project samples/AgentConsole -- \
  http://localhost:5003/wallet/charge --ap http://localhost:5301 \
  --ps http://localhost:5100 --signing-mode jwt
```

## Granting consent

The isolated demo admin endpoint can pre-grant consent for the AP-assigned
agent, resource and scope. Replace the illustrative `agent` values below with
the assigned ID printed by enrollment, not the `--sub` local cache label. These are local demo operations,
not production authorization APIs. Normal browser consent binds authenticated
person/session/key/account context; the code alone is not approval.

```bash
# Baseline / RBAC endpoints use scope "calendar.read"
curl -X POST http://localhost:5100/admin/consent \
  -H 'content-type: application/json' \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5001","scope":"calendar.read"}'

# The /events/write endpoint requires the elevated scope
curl -X POST http://localhost:5100/admin/consent \
  -H 'content-type: application/json' \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5001","scope":"calendar.write"}'
```

## Enrollment lifetime

AgentConsole caches the local key handle and endpoint metadata, not the token.
Each launch performs signed, idempotent reenrollment with the persisted key.
The sample AP stores ownership in SQLite and assigns the actual agent ID.
AP restart therefore does not require deleting the key or cache.

The sample AP does not implement authorized durable-key or Person Server
rotation. Use distinct local cache labels for separately provisioned identities;
do not treat key replacement or changed PS data as an implicit update.
The generic `hwk` demonstration does not refresh. JWT uses the owned enrolled
pipeline; the generic `jkt-jwt` example explicitly obtains one ephemeral pair.
