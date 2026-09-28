# AAuth Guided Tour

## Overview

A Blazor Server walk-through of the AAuth protocol flows, aimed at folks
learning the spec for the first time. It runs the same SDK code that
`samples/AgentConsole` does, but pauses between each step so you can see
the signature base, the JWTs, and the request/response payloads at every
hop.

The separate [Document Release](../../docs/workflows/document-release.md) page
at `/documents` executes resource permission before PS consent, followed by a
signed download or terminal denial. Its shared session and Playwright cases are
also used by SampleApp.

## What you'll see

![Tour Screenshot](tour-screenshot.png)

The root page (`/`) is an **Overview** that introduces Aria — the AI
travel assistant used throughout the demos — and indexes every flow with
a one-line description of what Aria is trying to do. Each card deep-links
into the live walkthrough at `/tour?flow=<Flow>`; the tour's topbar has an
**← Overview** link back.

A swim-lane sequence diagram across up to four actors — **Agent**,
**Concierge**, **Resource**, **Person Server** — with a payload
inspector on the right that decodes each JWT and shows the canonical
RFC 9421 signature base for captured signed requests. Core flows are
switchable at runtime from the topbar **Mode** picker:

* **Bootstrap** (2–3 steps) — generate the agent's signing key and build
  (or obtain) an agent token. Default.
* **Identity-based** (2 steps) — resource trusts the agent token directly;
  no PS involvement.
* **Resource-Managed (Two-Party)** (6 steps) — two-party flow where the
  **Inbox** resource manages authorization itself: no Person Server, no
  token exchange. The signed `GET /messages` returns `202` with an
  `AAuth-Requirement` pointing at the Inbox's own consent page; after you
  approve there, the Inbox issues an opaque `AAuth-Access` token bound to
  the agent's signature, which the agent replays to read the inbox.
* **PS-Asserted (Direct Grant)** (8 steps) — three-party flow: the resource
  answers the agent token with `requirement=person-token`, the agent gets an
  `aa-person+jwt` from the PS's `person_token_endpoint` and presents it, and
  the resource returns a resource token naming it (`presented_jti`). The PS
  mints the `auth_token` synchronously; no user interaction.
* **PS-Asserted (Deferred)** (11 steps) — the same person-token leg, then the
  PS parks the token request on `202 Accepted` and asks the user to consent
  before the `auth_token` is issued.
* **Call Chain / Multi-Agent** (9 steps; 15 when both hops need consent) — the
  agent calls a Concierge (intermediate service) which chains downstream to a
  Resource with the agent's auth token as `upstream_token`. Both grants name
  the same person (`ps`), each resource with its own directed `sub`; auth
  tokens carry no `agent` or `act` claim.
* **Federated (Four-Party)** (9 steps; 12 on the interactive path) — the
  resource has its own **Access Server**. The resource token's `aud` is the
  AS, so the PS federates to the AS, which evaluates policy and mints the
  `aa-auth+jwt` (`dwk=aauth-access.json`). A dedicated red **Access Server**
  swimlane is shown. With a Keycloak AS policy the AS returns `202
  requirement=interaction`; the PS relays it and the agent surfaces the
  Keycloak login URL. Requires an Access Server URL (`AccessServerUrl`);
  run it with `make demo-keycloak` (Keycloak) or `make demo`
  (stub AS, no Docker).
* **Mission (PS-Governed)** (21 steps; three prompts) — the optional,
  orthogonal **agent governance** layer (§Agent Governance). The agent
  proposes a human-approved mission, then names its `mission_s256` when it
  requests a person token; the resource copies it into the resource token and
  the PS evaluates every token, permission and audit request against the
  mission. Requires a Person Server URL; drive the same flow from the CLI with
  `make demo-mission`.
* **Mission + Call Chain** (15 steps; two prompts) — one durable mission
  governs two very different kinds of access. An out-of-mission elevated
  scope first triggers a **clarification chat** (the PS asks *why*, the
  agent answers) before the user approves it; then a **mission-governed
  call chain** (Agent → Concierge → Trips) flows **silently** because
  both hops are in the mission's scope. The PS's mission log records the
  whole trail. Requires a Person Server and a Concierge URL.

When `PersonServerUrl` is empty in `appsettings.json`, the three-party
options are disabled; the two-party flows — **Identity-based** and
**Resource-Managed (Two-Party)** — still run, since neither needs a Person
Server. You can also set the default in `appsettings.json`:

```json
"GuidedTour": { "Mode": "Deferred" }
```

The Generic Signature Keys flow exposes HWK, direct `jwks` and naming-JWT
demonstrations. AAuth resource flows use `jwt`, including Inbox's two-party flow.

Additional overview/navigation entries run shared scenarios:

- `/wallet-protocol`: AS clarification with answer/cancel, direct-AS chaining,
   and federated revocation/recovery. [Steps and sequence](../../docs/workflows/wallet-protocol.md)
- `/catalog-gateway`: five steps covering service selection, colliding `list`
   operations, sibling rejection and recovery. [Catalog guide](../../docs/workflows/catalog-gateway.md)
- `/events`: six steps for public/protected subscriptions, self-jwt delivery and
   durable verified agent receipts. [Events guide](../../docs/workflows/events.md)

Bookings includes personal/work accounts and per-call proposals; Sub-agent
uses distinct parent/worker keys and a four-party AS grant. Their app-local
Playwright specs use the existing shared harness, as do the additional pages.

Each Aria resource server serves its flow from isolated, per-mode endpoints.
**Profile** (:5000) handles Identity-based access: `GET /pseudonymous` and
`GET /anchored` (pseudonymous), `GET /identified` (agent identity).
**Inbox** (:5004) handles two-party resource-managed access (`GET /messages`,
scope `inbox.read`): it runs its own consent page and issues an opaque
`AAuth-Access` token bound to the agent's signature — no Person Server or
Access Server. **Calendar** (:5001) handles three-party PS-asserted access: `GET /events`
(scope `calendar.read`), `GET /events/write` (elevated scope `calendar.write`),
and `GET /events/admin` (RBAC roles + groups); the tour exercises the base
`GET /events` path. **Trips** (:5002) handles mission-governed access
(`GET /trips`, `GET /trips/book`), and **Wallet** (:5003) handles four-party
federated access (`GET /wallet`, `GET /wallet/charge`).

### Bootstrap (2–3 steps)

When no Agent Provider URL is configured (local bootstrap):

1. Generate Ed25519 keypair.
2. Build agent token — agent self-signs an `aa-agent+jwt` (demo mode).

When `AgentProviderUrl` is set, the tour enrols with a real AP:

1. Generate Ed25519 keypair.
2. Discover Agent Provider — `GET /.well-known/aauth-agent.json` to learn
   the AP's `enrol_endpoint`.
3. Enrol with Agent Provider: body-bound `hwk` signed `POST /enrol` with `{jwk}`;
   the AP assigns an identity and issues `aa-agent+jwt`.

### Identity-based (2 steps)

Assumes the agent is already bootstrapped (key + token exist).

1. Discover resource metadata — unsigned `GET /.well-known/aauth-resource.json`.
2. Signed `GET /pseudonymous` or `GET /identified` → 200 + claims (path depends on signing mode picker).

### Resource-Managed (Two-Party) (6 steps)

Assumes the agent is already bootstrapped. Two-party — no Person Server and
no token exchange; the **Inbox** manages authorization itself.

1. Discover Inbox metadata — unsigned `GET /.well-known/aauth-resource.json`
   (`access_mode=session-token` + `authorization_endpoint`).
2. Signed `GET /messages` → **`202 Accepted`** with `Location: /pending/{id}`
   and an `AAuth-Requirement: interaction` pointing at the Inbox's own consent
   page + single-use code.
3. Agent surfaces the user-facing `{url}?code={code}` link to the Inbox's own
   consent page.
4. **User approves at the Inbox.** The consent page opens in a new tab; the
   user clicks **Approve** and the Inbox records consent. No Person Server is
   involved.
5. Agent polls `Location` with a signed `GET` until the Inbox responds
   **`200`** with an opaque `AAuth-Access` token (token68) bound to the
   agent's signature.
6. Replay `GET /messages` carrying `Authorization: AAuth <token>` → 200 +
   messages (scope `inbox.read`). The signature covers the `authorization`
   header, proving the token is bound to the agent's key.

### PS-Asserted / Direct Grant (8 steps)

Assumes the agent is already bootstrapped.

1. Discover resource metadata — unsigned `GET /.well-known/aauth-resource.json`.
2. Signed `GET /events` with the agent token → **`401`** with
   `AAuth-Requirement: requirement=person-token` (no resource token).
3. Discover Person Server — unsigned `GET /.well-known/aauth-person.json`
   (`person_token_endpoint` + `auth_token_endpoint`).
4. Signed `POST /person {resource}` → **`200`** + `person_token`
   (`aa-person+jwt`: `aud` = Calendar, directed `sub`, `cnf` = agent key).
5. Signed `GET /events` presenting the person token → **`401`**
   `requirement=auth-token` with a `resource_token`.
6. Parse the resource token (`ps`, `sub`, `presented_jti`, `agent_jkt`).
7. Signed `POST /token {resource_token, presented_token}` → **`200`** +
   `auth_token` naming the person (`ps`, `sub`).
8. Signed `GET /events` carrying the `auth_token` → 200 + claims.

### PS-Asserted / Deferred (11 steps)

Steps 1–6 are the same as **Direct Grant**. From step 7 onward:

<!-- markdownlint-disable-next-line MD029 -->
7. Signed `POST /token` → **`202 Accepted`** with `Location: /pending/{id}`
   and interaction URL + single-use code.
8. Agent surfaces the user-facing `{url}?code={code}` link.
9. **User opens the PS's consent page.** The "Open consent page ↗"
   button opens `{url}?code={code}` in a new browser tab. The Person
   Server renders its own consent screen (agent + resource + scope); the
   user clicks **Approve** or **Deny** there and the PS records the
   choice. The agent is not on this channel. A "Simulate deny" button in
   the tour topbar is wired to the same denial endpoint for quick
   exercising of the denial path.
10. Agent polls `Location` with a signed `GET`. While polling, the
   sequence diagram shows a loop box with a live spinner and poll count.
   The loop resolves in one of three ways:
    * **Approve** → 200 + `auth_token`; the loop box turns solid green.
    * **Deny** → 403 + `{"error":"denied"}` → SDK throws
      `AAuthInteractionDeniedException`; the loop box turns red.
    * **Polling budget expires** (5 minutes by default) → SDK throws
      `AAuthInteractionTimeoutException`; the loop box turns amber.
11. Signed `GET /events` carrying the `auth_token` → 200 + claims (only on the
   approve path).

### Call Chain / Multi-Agent (9 steps)

Demonstrates multi-agent delegation. The agent calls a Concierge
(an intermediate AAuth-protected service) which itself calls a downstream
Resource (Calendar), passing the caller's auth_token as `upstream_token` on
its own person token and auth token requests. The PS issues the downstream
grant for the same person (`ps`) with a `sub` directed at Calendar; auth tokens
name the person, not the agents.

1. Discover Concierge metadata — unsigned `GET /.well-known/aauth-resource.json`.
2. Signed `GET /` → **`401`** `requirement=person-token`.
3. Discover Person Server — unsigned `GET /.well-known/aauth-person.json`.
4. Signed `POST /person {resource: Concierge}` → **`200`** + `person_token`.
5. Signed `GET /` presenting the person token → **`401`** + `resource_token`.
6. Parse the Concierge's resource token.
7. Signed `POST /token` (exchange, with `presented_token`) → **`200`** +
   `auth_token` scoped to the Concierge.
8. Signed `GET /` carrying the `auth_token` → **`200`**. Internally the
   Concierge performs its own person-token/challenge/exchange/retry cycle
   against Calendar's `GET /events` endpoint, shown as sub-step arrows in the
   sequence diagram.
9. Inspect multi-agent result — the upstream and downstream grants share the
   same `ps`, each with its own directed `sub`.

When neither hop has standing consent the flow grows to 15 steps: the
exchange at step 7 returns `202` (hop 1 consent + poll), and the retry returns
the Concierge's own `202` for the Concierge → Calendar hop (hop 2 consent +
poll of the Concierge's pending URL).

> [!TIP]
> The PS-Asserted (Deferred) flow only fires when the Person Server is
> configured with `MockPersonServer:RequireConsent=true`. `make demo` from
> the repo root launches the complete sample stack with consent gating enabled.

## Run it

### Option 1: `make demo` (recommended)

From the repo root:

```bash
make demo
```

Starts the resource servers (Profile, Inbox, Calendar, Trips, Wallet), Concierge,
MockPersonServer (with `RequireConsent=true`), MockAgentProvider, and the Guided
Tour together. Open <http://localhost:5400> and flip the topbar mode picker to
**Call Chain** or **Deferred** to exercise those paths.

### Option 2: separate terminals

```bash
# Terminal 1 — Resource servers (Profile :5000, Inbox :5004, Calendar :5001, Trips :5002, Wallet :5003)
make resources

# Terminal 2 — Concierge (port 5200)
dotnet run --project samples/Concierge

# Terminal 3 — Person Server (port 5100)
MockPersonServer__RequireConsent=true dotnet run --project samples/MockPersonServer

# Terminal 4 — Agent Provider (port 5301)
dotnet run --project samples/MockAgentProvider

# Terminal 5 — Tour UI (port 5400)
dotnet run --project samples/GuidedTour
```

Then open <http://localhost:5400> and click **Run all** (or step through
with **Run step**).

## Configuration

`appsettings.json`:

| Key | Default | Meaning |
| --- | --- | --- |
| `GuidedTour:ProfileUrl` | `http://localhost:5000` | Profile (Identity-based) resource server base URL. |
| `GuidedTour:InboxUrl` | `http://localhost:5004` | Inbox (resource-managed, two-party) resource server base URL. |
| `GuidedTour:CalendarUrl` | `http://localhost:5001` | Calendar (PS-asserted) resource server base URL. |
| `GuidedTour:TripsUrl` | `http://localhost:5002` | Trips (mission-aware) resource server base URL. |
| `GuidedTour:WalletUrl` | `http://localhost:5003` | Wallet (federated) resource server base URL. |
| `GuidedTour:ConciergeUrl` | `http://localhost:5200` | Concierge base URL for the call-chain flow. Set empty to disable that picker option. |
| `GuidedTour:PersonServerUrl` | `http://localhost:5100` | PS base URL. Set empty to lock the picker to identity-based mode. |
| `GuidedTour:AgentProviderUrl` | `http://localhost:5301` | AP base URL. When set, bootstrap enrols with the real AP instead of self-signing. |
| `GuidedTour:AgentId` | `aauth:tour-agent@ap.example` | Value placed in the agent token's `sub`. |
| `GuidedTour:Mode` | `Bootstrap` | Default flow on startup. `Bootstrap`, `Identity`, `ResourceManaged`, `Autonomous` (Direct Grant), `Deferred`, `CallChain`, `Federated`, or `Mission`. The topbar picker overrides this at runtime. |

