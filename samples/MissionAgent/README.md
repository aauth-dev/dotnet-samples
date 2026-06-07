# MissionAgent

A console showcase of the AAuth **mission** model, with the Person Server (PS)
acting as the policy-enforcement point for everything the agent does.

A *mission* is a durable, human-approved statement of intent plus the tools the
agent may use (§Missions). Once approved, the PS governs every downstream token
and permission request **under** that mission with a three-gate model
(§Agent Token Request):

| Gate | Situation | Outcome |
| --- | --- | --- |
| 1 | Mission terminated | Rejected outright |
| 2a | (resource, scope) is in the mission's approved scope | Granted silently |
| 2b | Already consented earlier in this mission | Granted silently |
| 3 | Out of scope | The user is prompted to decide |

### Scope (remote) vs tool (local)

A mission grants two distinct kinds of authority, and they travel through
different PS endpoints:

- **Scope — remote.** A scope authorizes access to a remote **resource** (an
  API). The resource defines its scopes and protects its endpoints with them;
  the granted scope is carried in an **auth token** the PS mints during the
  challenge → exchange → retry flow (§Scopes). The gate table above governs
  scope requests at the PS **token endpoint**.
- **Tool — local.** A tool is an action the agent runs **itself** (a tool call,
  file write, sending a message) — no resource is involved. Tools are governed
  at the PS **permission endpoint**: a mission's `approved_tools` are
  pre-approved and resolve without a PS round-trip, while any other action is
  referred to the user (§Permission Endpoint).

So `whoami` and `whoami:elevated_scope` are **scopes** (steps 3–5, via the
token endpoint) and `send_email` / `delete_inbox` are **tools** (steps 6–7, via
the permission endpoint).

This sample drives the whole lifecycle against the live mock servers:

```text
MockAgentProvider (:5301)  ->  MockPersonServer (:5100)  ->  WhoAmI (:5000)
        enrol                       govern                 mission-aware
                                                            resource
```

## What it demonstrates

1. **Enrol** with the Agent Provider to obtain a signing key + agent token.
2. **Propose a mission** (with two approved tools) — the PS returns the signed
   approval blob and its `s256` thumbprint.
3. **Access a mission-aware resource** (`WhoAmI /jwt/mission`). The resource
   copies the mission claim from the signed `AAuth-Mission` header into the
   resource token it issues (§Terminology), so the PS governs the exchange.
   `whoami` is **mission-approved** by default, so this call is granted
   **silently** (gate 2a — in scope), matching the SampleApp mission demo.
4. **Access it again** — still granted **silently** (gate 2a, in scope).
5. **Access an elevated scope** (`WhoAmI /jwt/mission/elevated`, requiring
   `whoami:elevated_scope`). This scope falls **outside** the mission's intent,
   so the PS prompts (gate 3) — out-of-mission scopes are never
   auto-denied (§Scopes).
6. **Request a pre-approved tool** permission (`send_email`) — granted silently,
   without ever calling the PS (§Permission Endpoint).
7. **Request a non-pre-approved tool** permission (`delete_inbox`) — the PS is
   consulted and the user is prompted.
8. **Report an action** to the audit endpoint (§Audit Endpoint).
9. **Ask the user a question** via the interaction endpoint.
10. **Propose mission completion**, which terminates the mission.

## How the flow works

There are three parties. The agent never talks to a resource with a long-lived
credential — every resource call is brokered by the agent's **Person Server**,
which is the single point that enforces the mission.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Agent as MissionAgent (CLI)
    participant AP as Agent Provider<br/>:5301
    participant PS as Person Server<br/>:5100
    participant R as WhoAmI<br/>:5000 /jwt/mission

    Note over Agent,AP: One-time bootstrap
    Agent->>AP: enrol (durable key)
    AP-->>Agent: agent token (short-lived, signed)

    Note over User,PS: Mission creation — the human approves intent + tools
    Agent->>PS: POST /mission {description, tools}
    rect rgb(124, 58, 237)
        Note over User,PS: 🖥️ BROWSER CONSENT SCREEN — "start a new mission?"<br/>shows the mission description + the tools it may use
        PS->>User: approve this mission?
        User-->>PS: ✅ approve
    end
    PS-->>Agent: signed approval blob + s256 thumbprint

    Note over Agent,R: Access a mission-aware resource — whoami is mission-approved
    Agent->>R: GET /jwt/mission + AAuth-Mission: {approver, s256}
    R-->>Agent: 401 + resource token (mission claim copied in)
    Agent->>PS: exchange resource token for an auth token
    Note right of PS: Token gate: whoami is in scope (gate 2a)
    PS-->>Agent: auth token granted silently — no prompt
    Agent->>R: GET /jwt/mission + Authorization: auth token
    R-->>Agent: 200 — echoes the mission reference

    Note over Agent,R: Access an ELEVATED scope — out of the mission's intent
    Agent->>R: GET /jwt/mission/elevated + AAuth-Mission: {approver, s256}
    R-->>Agent: 401 + resource token (whoami:elevated_scope)
    Agent->>PS: exchange resource token for an auth token
    Note right of PS: whoami:elevated_scope is out of the mission scope
    rect rgb(124, 58, 237)
        Note over User,PS: 🖥️ BROWSER CONSENT SCREEN — out-of-mission scope<br/>shows the mission, then "whoami:elevated_scope falls<br/>outside the mission intent" → approve access?
        PS->>User: out of mission — approve elevated access?
        User-->>PS: ✅ approve
    end
    PS-->>Agent: elevated auth token (consent accrues to the mission)
    Agent->>R: GET /jwt/mission/elevated + Authorization: auth token
    R-->>Agent: 200 — elevated claims

    Note over Agent,PS: Permission for a local action (no resource involved)
    Agent->>PS: POST /permission {action: send_email}
    Note right of PS: send_email is a pre-approved tool
    PS-->>Agent: granted silently — no user prompt
    Agent->>PS: POST /permission {action: delete_inbox}
    Note right of PS: delete_inbox is NOT a pre-approved tool
    rect rgb(124, 58, 237)
        Note over User,PS: 🖥️ BROWSER CONSENT SCREEN — local action<br/>shows the mission + approved tools, then<br/>"delete_inbox is not pre-approved" → approve?
        PS->>User: approve this action?
        User-->>PS: ✅ approve
    end
    PS-->>Agent: granted
```

> 🖥️ The **purple** blocks are the three browser-based **consent screens** (the
> PS's `/interaction` page). **(1) Mission creation** — the human approves the
> mission's intent and the tools it may use; this is the authority every later
> request is checked against. **(2) Out-of-mission scope** — the elevated
> `whoami:elevated_scope` falls outside the mission's intent, so the PS asks
> before issuing the elevated token. **(3) Out-of-tool permission** — a local
> `action` (`delete_inbox`) that isn't one of the mission's `approved_tools`, so
> the PS asks. The `whoami` token gate (steps 3–4) and the pre-approved
> `send_email` tool (step 6) are granted **silently** and never reach a screen.
> In `--auto` mode each screen is resolved by the PS's scripted default instead
> of a human click, but they are the same decision points.
>
> The spec distinguishes the two words: a mission pre-approves **`approved_tools`**
> (tools), while each per-call permission request carries an **`action`**. The
> agent calls the permission endpoint only for actions not covered by a
> pre-approved tool (§Permission Endpoint).


### The token gate — why the whoami calls are silent

When the PS is asked to mint an auth token under a mission, it runs a
**three-gate** decision (§Agent Token Request). Crucially, this gate is about
**resource + scope**, *not* about the approved tools:

```mermaid
flowchart TD
    A[Token request under a mission] --> G1{Mission terminated?}
    G1 -- yes --> D1[Reject: 403 mission_terminated]
    G1 -- no --> G2a{Is resource+scope in the<br/>mission's in-scope set?}
    G2a -- yes --> S1[Grant silently — reason: InScope]
    G2a -- no --> G2b{Already consented for this<br/>resource+scope this mission?}
    G2b -- yes --> S2[Grant silently — reason: PriorConsent]
    G2b -- no --> P[Prompt the user — reason: OutOfScope]
    P -- approve --> S3[Grant + remember the consent]
    P -- deny --> D2[Reject: access denied]
```

A mission carries **two independent** notions of "approved":

- **Approved tools** (`send_email`, `summarize`) gate the **permission**
  endpoint (step 6/7), *not* token issuance.
- **In-scope `(resource, scope)` pairs** gate **silent token issuance**
  (gate 2a). By default this sample declares `whoami` as mission-approved
  (mirroring the SampleApp mission demo), so the calls to
  `WhoAmI /jwt/mission` (`resource=:5000`, `scope=whoami`) match **gate 2a** and
  are granted **silently** — no prompt. The elevated `whoami:elevated_scope` is
  **not** in scope, so it falls through to **gate 3 → prompt** (step 5).

> To see the **out-of-scope prompt** for `whoami` instead, replace the default
> in-scope set so it no longer contains `whoami` (for example
> `--mission-approved whoami:elevated_scope`). The first `whoami` call then hits
> **gate 3 → prompt**; once you approve, the PS records the consent and the
> **second** call hits **gate 2b (prior consent)** and is silent. That
> prompt → prior-consent contrast is exactly what the default `whoami` grant
> skips.

## Running it


Start the three servers (each in its own terminal):

```bash
dotnet run --project samples/MockAgentProvider   # :5301
dotnet run --project samples/MockPersonServer     # :5100
dotnet run --project samples/WhoAmI               # :5000
```

Then run the agent:

```bash
dotnet run --project samples/MissionAgent
```

### Using the Makefile

The repo ships two convenience targets. Start the backend stack (AP + PS +
WhoAmI) in one terminal:

```bash
make demo-mission
```

Then drive the agent from another terminal:

```bash
make agent-mission                                       # interactive (decide in your browser)
make agent-mission MISSION_APPROVED=whoami:elevated_scope # silence the elevated scope instead of whoami
make agent-mission AUTO=1                                 # unattended (scripted PS defaults — no browser screens)
```

`MISSION_APPROVED="<scope>..."` maps to `--mission-approved <scope>` and `AUTO=1`
maps to `--auto` (both described below). By default `whoami` is mission-approved,
so the WhoAmI token gate is silent; pass a different `MISSION_APPROVED` set to
change which scopes are in-scope. Under `AUTO=1` there are no browser screens, so
the in-scope set only changes the PS's decision reason (silent `InScope` at gate
2a vs a scripted out-of-scope approval) — handy for tests, not for a human
watching.

By default each out-of-scope prompt is **interactive**: the agent prints the
Person Server's consent URL (and tries to open it) and waits while you click
**Approve** or **Deny** in your browser. The PS holds the request at `202` until
you decide, then the agent's next poll resolves.

For an unattended run (CI, smoke tests), use `--auto` to resolve every prompt
via the PS's scripted defaults:

```bash
dotnet run --project samples/MissionAgent -- --auto
```

### Mission-approved scopes (controlling the silent set)

By default the mission declares `whoami` as **in scope**, so the WhoAmI token
gate (steps 3–4) is granted **silently** at gate 2a (reason `InScope`) and no
token consent screen appears — matching the SampleApp mission demo. The
`--mission-approved <scope>` flag **replaces** this default set so you can choose
which scopes are silent:

```bash
# default: whoami is in scope, so the WhoAmI token gate is silent
dotnet run --project samples/MissionAgent

# silence the elevated scope instead — now the FIRST whoami call is out of
# scope and prompts (gate 3), then the second is silent via prior consent (2b)
dotnet run --project samples/MissionAgent -- --mission-approved whoami:elevated_scope

# or, via the Makefile:
make agent-mission MISSION_APPROVED=whoami:elevated_scope
```

Each scope is seeded against the resource's **origin** (`http://localhost:5000`),
which is what the PS compares against the resource token's `iss`. Pass
`--mission-approved` more than once to declare several scopes in scope; the first
use clears the default `whoami` grant.

## Options

| Flag | Default | Description |
| --- | --- | --- |
| `--ap <url>` | `http://localhost:5301` | Agent Provider base URL |
| `--ps <url>` | `http://localhost:5100` | Person Server base URL |
| `--resource <url>` | `http://localhost:5000/jwt/mission` | Mission-aware resource endpoint |
| `--sub <agent-id>` | `aauth:mission-demo@ap.example` | Agent identifier to enrol as |
| `--mission-approved <scope>` | `whoami` | Replace the default in-scope set; each `(resource origin, scope)` is granted silently (gate 2a). Repeatable; the first use clears the default |
| `--auto` | _(off)_ | Resolve prompts via scripted PS defaults instead of waiting for a browser decision |
