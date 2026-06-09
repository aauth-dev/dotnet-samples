# Research — Splitting the WhoAmI resource server into focused servers

> Research-only document. No task lists or implementation steps. See the
> companion `implementation-plan.md` (created later) for phased work.

## Goal

Today a single resource server — `samples/WhoAmI` — demonstrates **every**
AAuth access mode and token type from one ASP.NET host, routed by path
(`/hwk`, `/jkt-jwt`, `/jwks-uri`, `/jwt`, `/jwt/admin`, `/jwt/roles`,
`/jwt/mission`, `/jwt/mission/elevated`, `/federated`). The owner wants to:

1. Break WhoAmI into **multiple smaller resource servers**, split by path /
   concern, so each server's `Program.cs` is short and demonstrates **one**
   idea clearly.
2. Adopt a **relatable narrative** (real-feeling services + meaningful scopes)
   instead of the abstract `whoami` / `whoami:admin` / `whoami:elevated_scope`
   / `whoami-admin` taxonomy.
3. Refactor WhoAmI and **update every sample and doc** to align.

This document captures the current state, the cross-repo usage inventory, the
problems with the present design, and a menu of **narrative options** for the
owner to choose from. Scope/path naming is deliberately presented as options,
not yet decided.

## Current state — one server, nine paths

Source: [samples/WhoAmI/Program.cs](../../../samples/WhoAmI/Program.cs).
A fresh signing key is generated on startup (`AAuthKey.Generate()`, kid
`whoami-1`); the host trusts MockPersonServer (`:5100`) and MockAccessServer
(`:5500`). One `UseWhen` branch per path builds an isolated verification /
challenge pipeline.

| Path | Access mode demonstrated | Verification | Scope / role gate |
|---|---|---|---|
| `/` | index (no auth) | none | none |
| `/hwk` | pseudonymous (signature only) | `RequireIssuerVerification=false` | none |
| `/jkt-jwt` | pseudonymous + key delegation (naming JWT) | signature only | none |
| `/jwks-uri` | agent identity (key via JWKS) | signature only | `AAuth.Identified` |
| `/jwt` | three-party (PS-asserted) baseline | full issuer verification | `whoami` |
| `/jwt/admin` | three-party step-up scope | full | `whoami:admin` |
| `/jwt/roles` | three-party RBAC | full | role `whoami-admin` |
| `/jwt/mission` | three-party mission-aware | full + `MissionAware` | `whoami` |
| `/jwt/mission/elevated` | mission-aware, out-of-mission scope gate | full + `MissionAware` | `whoami:elevated_scope` |
| `/federated` | four-party (AS-issued auth token) | full, trusts AS issuer | `whoami` |

### Scope / role taxonomy in use today

| Identifier | Kind | Meaning in the demo |
|---|---|---|
| `whoami` | scope | basic profile read (baseline) |
| `whoami:admin` | scope | elevated/step-up profile access |
| `whoami:elevated_scope` | scope | mission out-of-scope consent demo |
| `whoami-admin` | role | RBAC role asserted by the PS |

These names describe the **protocol mechanism** (step-up, RBAC, out-of-mission)
rather than any **resource semantics** — there is nothing a `whoami:admin`
token actually lets you *do* beyond echo claims. A newcomer must mentally map
"`/jwt/admin` ⇒ three-party ⇒ elevated scope" instead of reading an intent.

## Cross-repo usage inventory

The WhoAmI paths, scopes, role, and `:5000` origin are referenced from many
places. Any rename/split must touch all of them. Verified references below.

### Sample code

| Project | Reference(s) | Notes |
|---|---|---|
| AgentConsole | [Program.cs#L261-L264](../../../samples/AgentConsole/Program.cs#L261-L264) | mode→path map: `hwk→/hwk`, `jkt-jwt→/jkt-jwt`, `jwks_uri→/jwks-uri`, default `/jwt` |
| GuidedTour | [appsettings.json#L10](../../../samples/GuidedTour/appsettings.json#L10) `WhoAmIUrl`; [TourOptions.cs#L70](../../../samples/GuidedTour/TourOptions.cs#L70); `Components/EntityHighlighter.cs` | playwright specs assert `scope==['whoami']`, hit `/jwt`, `/federated`, `/jwt/mission`, `/jwt/mission/elevated` |
| SampleApp | `appsettings.json` `Resource=:5000`; pages `Hwk/JwksUri/JktJwt/Jwt/Deferred/Federated/CallChain/Mission/MissionCallChain.razor` | hard-codes `/hwk`, `/jkt-jwt`, `/jwks-uri`, `/jwt`, `/federated`, `/jwt/mission/elevated`; in-page `AddAAuthScopePolicy("AAuth.Scope.whoami", ...)` snippets |
| Orchestrator | [Program.cs#L26-L29](../../../samples/Orchestrator/Program.cs#L26-L29) `Downstream=:5000`, own scope `orchestrate`; `PendingStore.cs` default downstream path `/jwt` (also `/jwt/mission`) | acts as **both** resource (scope `orchestrate`) and agent calling WhoAmI |
| MissionAgent | [Program.cs#L34-L48](../../../samples/MissionAgent/Program.cs#L34-L48) | `ResourceScope="whoami"`, `ElevatedScope="whoami:elevated_scope"`, resource hard-coded `:5000/jwt/mission` |
| LiveWhoAmITest | `Program.cs` `WhoAmIUrl=https://whoami.aauth.dev/` | external live server; out of local-refactor scope but mirrors path semantics |
| MockPersonServer | `Program.cs` `PsScope="whoami"`, `PsAdminScope="whoami:admin"`, `demoRoles=["whoami-admin"]` | issues the scopes/role; seeds consent against `:5000` origin |
| MockAccessServer | `Policy/StubAccessPolicy.cs` (`whoami`, `whoami:admin`, `AdminRole="whoami-admin"`); `keycloak/realm-aauth.json` scopes + role; `appsettings.json` `ResourceName="whoami"` | four-party policy mirrors the scope tiers |
| MockAgentProvider | none direct | issues agent tokens only |

### Docs

| Doc | What it teaches with WhoAmI strings |
|---|---|
| [samples/README.md](../../../samples/README.md) | full endpoint matrix, all scopes/role, `:5000` |
| [docs/server/verification-middleware.md](../../../docs/server/verification-middleware.md) | per-mode `UseWhen` pipeline pattern (`/hwk`, `/jwks-uri`, `/jwt`, `/jwt/admin`) |
| [docs/server/challenge-middleware.md](../../../docs/server/challenge-middleware.md) | `/jwt` vs `/jwt/admin` challenge routing; `ResourceKeyId="whoami-1"` |
| [docs/server/authn-authz.md](../../../docs/server/authn-authz.md) | scope/role policy registration for `whoami`, `whoami:admin`, `whoami-admin` |
| [docs/server/token-issuance.md](../../../docs/server/token-issuance.md), [docs/reference/configuration.md](../../../docs/reference/configuration.md) | `DefaultScope="whoami"` |
| [docs/workflows/call-chaining.md](../../../docs/workflows/call-chaining.md) | `Agent → Orchestrator → WhoAmI`, downstream `/jwt` on `:5000` |
| [docs/workflows/federated-access.md](../../../docs/workflows/federated-access.md) | Keycloak realm models `whoami` + `whoami:admin` + admin role |
| [docs/getting-started.md](../../../docs/getting-started.md), [README.md](../../../README.md) | access-mode table → SampleApp `/hwk`, `/jwks-uri`, `/jwt`, `/deferred`, `/federated` |
| [samples/MissionAgent/README.md](../../../samples/MissionAgent/README.md), [samples/GuidedTour/README.md](../../../samples/GuidedTour/README.md), [samples/Orchestrator/README.md](../../../samples/Orchestrator/README.md), [samples/MockAccessServer/README.md](../../../samples/MockAccessServer/README.md) | mission endpoints, step-up, RBAC, four-party setup |
| [tests/e2e/README.md](../../../tests/e2e/README.md) | WhoAmI `:5000`, call-chain delegation |

> The repo's headline taxonomy already names **four access modes** (see
> [docs/getting-started.md#supported-flows](../../../docs/getting-started.md)):
> *Identity-Based*, *Resource-Managed*, *PS-Asserted (three-party)*,
> *Federated (four-party)*. The split below should reinforce that taxonomy, not
> invent a competing one.

## Problems with the single-server design

1. **Path encodes mechanism, not meaning.** `/jwt/admin`, `/jwt/roles`,
   `/jwt/mission/elevated` describe protocol internals. Learners must decode
   them; they teach nothing about *what the resource protects*.
2. **Branch disambiguation is noisy.** Because `/jwt`, `/jwt/admin`,
   `/jwt/roles`, `/jwt/mission`, `/jwt/mission/elevated` share a prefix, the
   general `/jwt` branch needs negative `&& !StartsWithSegments(...)` guards.
   This is the "complicated setup" the owner wants gone.
3. **Every concept shares one host's config** (one key, one trusted-PS set, one
   AS). Concepts that need different trust (four-party trusts the AS; three-party
   trusts the PS) are forced to coexist, obscuring each server's real config.
4. **Abstract scopes carry no story.** `whoami:admin` vs `whoami:elevated_scope`
   are indistinguishable to a newcomer; one is "step-up", the other is
   "out-of-mission", but the names don't say so.
5. **Copy-paste starting point is hard.** A developer wanting "a minimal
   three-party resource server" must extract one branch from a 500-line file.

### What "good" looks like after the split

- Each resource server is a small, self-contained `Program.cs` (well-known +
  one verification pipeline + a couple of endpoints) that a developer can copy
  as a starting template.
- Server names and scope names read like a real product, so docs can tell a
  story ("the assistant reads your calendar, then asks before spending money").
- The four headline access modes each have an obvious home.
- Cross-cutting demos (call-chaining, missions, deferred consent) compose the
  small servers instead of living inside the mega-server.

## Split principle (independent of narrative theme)

Regardless of the chosen theme, the recommendation is **one resource server per
access mode**, each with realistic scopes:

| New server (role) | Replaces WhoAmI path(s) | Access mode | Why it is its own host |
|---|---|---|---|
| Identity/low-stakes service | `/hwk`, `/jkt-jwt`, `/jwks-uri` | Identity-Based | signature-only verification, no PS trust needed |
| Core user-data service | `/jwt`, `/jwt/admin`, `/jwt/roles` | PS-Asserted (three-party) incl. step-up + RBAC | trusts the PS; baseline + elevated scope + role on **one** resource reads naturally as scope tiers of the same product |
| Mission-governed service | `/jwt/mission`, `/jwt/mission/elevated` | three-party + mission-aware | needs `MissionAware=true`; the elevated scope is the out-of-mission gate |
| Federated/enterprise service | `/federated` | Federated (four-party) | trusts the **AS** as issuer, `aud`=AS — a different trust model |

> Step-up (`/jwt/admin`) and RBAC (`/jwt/roles`) **can** stay as extra
> endpoints on the core user-data server (they are the same product's scope
> tiers) rather than separate hosts — this keeps the server count to ~4 while
> still isolating each *access mode*. Whether to split them further is an open
> question (see below).

The Orchestrator stays as the **call-chaining intermediary** (agent + resource)
and simply points its `Downstream` at the new core user-data service.

## Narrative options (please choose one)

> **Update (2026-06): Option A — "Aria, your AI travel assistant" was chosen,
> with no shared sample project (each server is a standalone, copy-paste
> `Program.cs`).** This resolves open questions #1 (4 servers, step-up + RBAC
> fold onto the Calendar server) and #3 (no shared library; the SDK already
> carries the reusable protocol plumbing). The chosen endpoint/scope map and the
> per-app flow mapping are recorded in the new sections below. The Option B / C
> tables are retained for history.

Each option keeps the same four-server structure above; only the **theme**,
**server names**, and **scope names** differ. Ports shown are suggestions
(today WhoAmI is `:5000`; the suite could use `:5000-5003`).

### Option A — "Aria, your AI travel assistant" (recommended)

Story: an AI assistant books a trip on a traveler's behalf. Every protocol
feature has a natural home in a trip-planning journey.

| Server | Port | Mode | Scopes / role | Maps from |
|---|---|---|---|---|
| **Profile** (`profile`) | 5000 | Identity-Based | _(none — identity only)_ | `/hwk`, `/jkt-jwt`, `/jwks-uri` |
| **Calendar** (`calendar`) | 5001 | PS-Asserted (3p) | `calendar.read`, `calendar.write` (step-up), role `calendar.owner` | `/jwt`, `/jwt/admin`, `/jwt/roles` |
| **Trips** (`trips`) | 5002 | three-party + mission | `trips.read`, `trips.book` (out-of-mission elevated) | `/jwt/mission`, `/jwt/mission/elevated` |
| **Wallet** (`wallet`) | 5003 | Federated (4p) | `wallet.read`, `wallet.charge` | `/federated` |

Narrative thread for docs: *"Aria reads your **calendar**, drafts a **trip**
under a mission you approved, then asks again before charging your **wallet**."*
Step-up = `calendar.write`; RBAC = `calendar.owner`; out-of-mission gate =
`trips.book`; cross-domain policy = the wallet's bank Access Server.

### Option B — "Acme personal-data suite" (productivity SaaS)

Story: an agent works across a person's productivity apps. Closest to common
OAuth demos (Google/Microsoft-style scopes), most familiar to API developers.

| Server | Port | Mode | Scopes / role | Maps from |
|---|---|---|---|---|
| **Directory** (`directory`) | 5000 | Identity-Based | _(none)_ | `/hwk`, `/jkt-jwt`, `/jwks-uri` |
| **Mail** (`mail`) | 5001 | PS-Asserted (3p) | `mail.read`, `mail.send` (step-up), role `mail.admin` | `/jwt`, `/jwt/admin`, `/jwt/roles` |
| **Drive** (`drive`) | 5002 | three-party + mission | `drive.read`, `drive.share` (out-of-mission elevated) | `/jwt/mission`, `/jwt/mission/elevated` |
| **Billing** (`billing`) | 5003 | Federated (4p) | `billing.read`, `billing.pay` | `/federated` |

Narrative thread: *"The assistant reads your **mail**, shares a **drive** file
under a mission, and the enterprise **billing** system enforces its own policy."*

### Option C — "Minimal protocol decomposition" (lowest churn)

Story: keep the abstract `whoami` identity concept; just split the mega-server
by mode and rename only where a prefix collision forced negative matching.
Scopes keep the `whoami` family. Smallest doc/test churn; least pedagogical
gain.

| Server | Port | Mode | Scopes / role | Maps from |
|---|---|---|---|---|
| **whoami-identity** | 5000 | Identity-Based | _(none)_ | `/hwk`, `/jkt-jwt`, `/jwks-uri` → each at `/` |
| **whoami** | 5001 | PS-Asserted (3p) | `whoami`, `whoami.admin`, role `whoami-admin` | `/`, `/admin`, `/roles` |
| **whoami-mission** | 5002 | three-party + mission | `whoami`, `whoami.elevated` | `/`, `/elevated` |
| **whoami-federated** | 5003 | Federated (4p) | `whoami` | `/` |

> Note: even Option C should drop the `whoami:elevated_scope` /
> `whoami:admin` colon names. Colons in scope strings are valid but the
> ad-hoc `:elevated_scope` reads like a placeholder; `.`-segmented scopes
> (`whoami.admin`) are clearer.

### Comparison

| Criterion | A (Travel) | B (SaaS) | C (Minimal) |
|---|---|---|---|
| Relatability for newcomers | high | high | low |
| Familiar to OAuth devs | medium | high | medium |
| Doc rewrite effort | high | high | low |
| Tells one connected story | strong | medium | none |
| Risk of "demo-y" feeling | low | low | n/a |

Recommendation: **Option A**. A single trip-planning storyline naturally
sequences identity → consent → mission → step-up → federation, which is exactly
the order the docs already introduce the access modes. Option B is a strong
fallback if a generic SaaS framing is preferred. Option C is only worth it if
minimizing churn outweighs the learning-curve win.

## Chosen design — "Aria" servers, endpoints, scopes

> **Preservation guarantee (non-goal: simplification).** This refactor does
> **not** remove or simplify any existing flow, step, gate, consent/pending
> branch, or example. Every GuidedTour flow (all 8), SampleApp page (all 10),
> AgentConsole signing mode + explicit-path example, MissionAgent step (all 10),
> and e2e/playwright spec is kept 1:1 — only **renamed** (mechanism-named →
> product-named) and **re-targeted** (new server/port/path/scope). The
> mechanism→product mapping is **lossless**: `whoami:admin`→`calendar.write`
> (step-up), `whoami-admin`→`calendar.owner` (RBAC incl. the deliberate 403),
> `whoami:elevated_scope`→`trips.book` (out-of-mission gate), `whoami`→
> `wallet.read` (federated). The **only** net-new endpoint is `/wallet/charge`
> (`wallet.charge`, role `wallet.payer`), which is additive — it gives the
> already-existing Keycloak role gate a federated home and never replaces the
> preserved `/wallet` baseline.

Four standalone resource servers replace the single WhoAmI host. Each is a small
`Program.cs` (well-known + one verification pipeline + a couple of endpoints).
No shared sample project — the reusable plumbing already lives in the SDK
(`AddAAuthResource`, `MapAAuthResourceWellKnown`, `AddAAuthScopePolicy` /
`AddAAuthRolePolicy`, `UseAAuthVerification`, `UseAAuthChallenge`). All four live
under `samples/MockResourceServers/` (one project subfolder each), grouping them
with the other demo backends (`MockPersonServer`, `MockAccessServer`,
`MockAgentProvider`).

> **SDK boundary (2026-06).** This refactor is sample + docs only, with **one
> deliberate SDK edit**: the PS and AS fallback `DefaultScope` changed from
> `"whoami"` to `""` (empty) in
> [AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)
> and
> [AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs).
> Rationale: the spec makes `scope` OPTIONAL
> ([draft-hardt-aauth-r3.md#L340](../../../aauth-spec/draft-hardt-aauth-r3.md)),
> and `AuthTokenBuilder` requires only "at least one of `sub` or `scope`" and
> omits an empty `scope` claim
> ([AuthTokenBuilder.cs#L141-L191](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L141-L191)).
> A scopeless resource token now mints a scopeless (sub-only) auth token instead
> of injecting `whoami`. Verified: solution builds 0/0; 387 unit + 481
> conformance + 38 PS/AS/WhoAmI integration tests pass. The remaining `whoami`
> strings in SDK XML-doc comments are cosmetic and out of scope. No other SDK
> behavior changes.

| Server | Port | Access mode | Endpoint | Signing mode | Scope / role | Replaces |
|---|---|---|---|---|---|---|
| **Profile** | 5000 | Identity-Based | `/pseudonymous` | `hwk` | _(none)_ | `/hwk` |
| | | | `/identified` | `jwks_uri` | _(none, `AAuth.Identified`)_ | `/jwks-uri` |
| | | | `/anchored` | `jkt-jwt` | _(none)_ | `/jkt-jwt` |
| **Calendar** | 5001 | PS-Asserted (3p) | `/events` | `jwt` | `calendar.read` | `/jwt` |
| | | | `/events/write` | `jwt` | `calendar.write` (step-up) | `/jwt/admin` |
| | | | `/events/admin` | `jwt` | role `calendar.owner` (RBAC) | `/jwt/roles` |
| **Trips** | 5002 | three-party + mission | `/trips` | `jwt` | `trips.read` (in-mission) | `/jwt/mission` |
| | | | `/trips/book` | `jwt` | `trips.book` (out-of-mission elevated) | `/jwt/mission/elevated` |
| **Wallet** | 5003 | Federated (4p) | `/wallet` | `jwt` | `wallet.read` (any user) | `/federated` |
| | | | `/wallet/charge` | `jwt` | `wallet.charge` (AS role `wallet.payer`) | _(new — gives the realm's role gate a federated home)_ |

Notes:

- **Profile** keeps three paths because they are three *signing modes* of one
  *access mode* (identity), and AgentConsole already maps `mode → path`. The
  paths use **outcome-based** names describing what the resource concludes — not
  the protocol scheme identifier: `/pseudonymous` (`hwk`, key thumbprint only),
  `/identified` (`jwks_uri`, named verifiable identity, keeps the
  `AAuth.Identified` policy), `/anchored` (`jkt-jwt`, an ephemeral key anchored
  to a durable enrollment key — the spec's "enrollment anchor" / naming-JWT
  refresh). The signing-mode identifiers (`hwk` / `jwks_uri` / `jkt-jwt`) are
  protocol scheme names and do **not** change; only the resource paths do.
- **Calendar** is the "core user-data" service. `calendar.read` is the baseline
  three-party scope; `calendar.write` is the step-up scope; `calendar.owner` is
  the RBAC role (PS-asserted, with the deliberate 403 path when absent).
- **Trips** is mission-aware (`MissionAware = true`). `trips.read` is inside a
  trip-planning mission's intent (silent grant); `trips.book` falls outside it
  (out-of-mission consent prompt).
- **Wallet** is four-party: the challenge issues a resource token with `aud` =
  the Access Server; the AS mints the auth token. The Wallet has **two**
  endpoints so the AS policy engine actually decides something:
  - `/wallet` (`wallet.read`) — view balance + saved cards; the AS grants this
    to any authenticated user (baseline, replaces today's single `/federated`).
  - `/wallet/charge` (`wallet.charge`) — initiate a payment; the AS grants this
    **only** to users carrying the `wallet.payer` role. This is the realistic
    home for the role gate that today lives as `whoami:admin` + `whoami-admin`
    in the Keycloak realm but has no federated endpoint. It reuses the existing
    two Keycloak users — `demo`/`demo` (payer → can charge) and `guest`/`guest`
    (read-only → 403 on charge) — turning
    [MockAccessServerKeycloakTests](../../../tests/AAuth.Tests/Integration/MockAccessServerKeycloakTests.cs)
    into a meaningful "demo can pay, guest can only look" story. The primary
    GuidedTour/SampleApp federated flow stays on `/wallet`; `/wallet/charge` is
    exercised by AgentConsole + the Keycloak tests (mirroring how `/jwt/admin`
    works today), so no new mandatory UI steps.
- **Orchestrator** stays the call-chaining intermediary (its own scope
  `orchestrate`) but now points `Downstream` at **Calendar** `/events`
  (`calendar.read`) instead of WhoAmI `/jwt` (`whoami`). Narrative: Aria → the
  Concierge (Orchestrator) → your Calendar.

### Mode → path mapping convention

Because the descriptive Profile paths no longer echo the scheme name, the
mapping must be discoverable in code and docs (not just memorized):

- **Inline comments** on each Profile endpoint stating the scheme it serves,
  e.g. `// sig=hwk → pseudonymous access (key thumbprint only)` above the
  `/pseudonymous` handler, and similarly for `/identified` (`jwks_uri`) and
  `/anchored` (`jkt-jwt`).
- **AgentConsole**: a comment on the `mode → path` switch
  ([Program.cs#L261-L264](../../../samples/AgentConsole/Program.cs#L261-L264))
  documenting `hwk→/pseudonymous`, `jwks_uri→/identified`, `jkt-jwt→/anchored`,
  `jwt→/events`.
- **Docs**: a small mapping table (scheme → Profile path → what the resource
  learns) added to the Profile sample README and referenced from
  [docs/signing-modes/overview.md](../../../docs/signing-modes/overview.md) so a
  reader can connect the `Signature-Key` scheme to the demo endpoint.

## Current → new flow mapping per app

Every existing demo flow keeps its pedagogy; only the target server, endpoint,
and scope strings change. Tables below pair each current flow with its Aria
replacement.

### GuidedTour (8 flows)

| Flow | Today: server · endpoint · scope | Aria: server · endpoint · scope |
|---|---|---|
| 1 · Bootstrap | none (key gen / AP enrol) | unchanged |
| 2 · Identity-Based | WhoAmI `/hwk` · `/jwks-uri` · `/jkt-jwt` — no scope | **Profile** `/pseudonymous` · `/identified` · `/anchored` — no scope |
| 3 · PS-Asserted (Direct Grant) | WhoAmI `/jwt` · `whoami` | **Calendar** `/events` · `calendar.read` |
| 4 · PS-Asserted (Deferred) | WhoAmI `/jwt` · `whoami` | **Calendar** `/events` · `calendar.read` |
| 5 · Call Chain | Orchestrator `/` (`orchestrate`) → WhoAmI `/jwt` (`whoami`) | Orchestrator `/` (`orchestrate`) → **Calendar** `/events` (`calendar.read`) |
| 6 · Federated (Four-Party) | WhoAmI `/federated` · `whoami` | **Wallet** `/wallet` · `wallet.read` |
| 7 · Mission (PS-Governed) | WhoAmI `/jwt/mission` (`whoami`, silent) + `/jwt/mission/elevated` (`whoami:elevated_scope`, prompt) | **Trips** `/trips` (`trips.read`, silent) + `/trips/book` (`trips.book`, prompt) |
| 8 · Mission + Call Chain | elevated WhoAmI `/jwt/mission/elevated` (`whoami:elevated_scope`); chain Orchestrator `/mission` (`orchestrate`) → WhoAmI (`whoami`) | elevated **Trips** `/trips/book` (`trips.book`); chain Orchestrator `/mission` (`orchestrate`) → **Trips** `/trips` (`trips.read`) |

### SampleApp (9 pages + Home)

| Page (route) | Today: server · endpoint · scope | Aria: server · endpoint · scope |
|---|---|---|
| `/` Home | navigation only | unchanged |
| `/hwk` | WhoAmI `/hwk` — no scope | **Profile** `/pseudonymous` — no scope |
| `/jwks-uri` | WhoAmI `/jwks-uri` — no scope | **Profile** `/identified` — no scope |
| `/jkt-jwt` | WhoAmI `/jkt-jwt` — no scope | **Profile** `/anchored` — no scope |
| `/jwt` | WhoAmI `/jwt` · `whoami` | **Calendar** `/events` · `calendar.read` |
| `/deferred` | WhoAmI `/jwt` · `whoami` | **Calendar** `/events` · `calendar.read` |
| `/federated` | WhoAmI `/federated` · `whoami` | **Wallet** `/wallet` · `wallet.read` |
| `/call-chain` | Orchestrator `/` (`orchestrate`) → WhoAmI `/jwt` (`whoami`) | Orchestrator `/` (`orchestrate`) → **Calendar** `/events` (`calendar.read`) |
| `/mission` | WhoAmI `/jwt/mission` (`whoami`) + `/jwt/mission/elevated` (`whoami:elevated_scope`) | **Trips** `/trips` (`trips.read`) + `/trips/book` (`trips.book`) |
| `/mission-call-chain` | WhoAmI `/jwt/mission/elevated` (`whoami:elevated_scope`); chain Orchestrator `/mission` → WhoAmI (`whoami`) | **Trips** `/trips/book` (`trips.book`); chain Orchestrator `/mission` → **Trips** `/trips` (`trips.read`) |

### AgentConsole (4 signing modes + 3 explicit-path examples)

| Invocation | Today: endpoint · scope | Aria: endpoint · scope |
|---|---|---|
| `--signing-mode hwk` | WhoAmI `/hwk` — no scope | **Profile** `/pseudonymous` — no scope |
| `--signing-mode jkt-jwt` | WhoAmI `/jkt-jwt` — no scope | **Profile** `/anchored` — no scope |
| `--signing-mode jwks_uri` | WhoAmI `/jwks-uri` — no scope | **Profile** `/identified` — no scope |
| `--signing-mode jwt` (default, `--ps`) | WhoAmI `/jwt` · `whoami` | **Calendar** `/events` · `calendar.read` |
| explicit `/jwt/admin` | WhoAmI `/jwt/admin` · `whoami:admin` | **Calendar** `/events/write` · `calendar.write` |
| explicit `/jwt/roles` | WhoAmI `/jwt/roles` · role `whoami-admin` | **Calendar** `/events/admin` · role `calendar.owner` |
| explicit `/federated` charge | _(none — no federated role endpoint today)_ | **Wallet** `/wallet/charge` · `wallet.charge` (AS role `wallet.payer`; `demo` allowed, `guest` 403) |

> The mode → path map in [AgentConsole/Program.cs#L261-L264](../../../samples/AgentConsole/Program.cs#L261-L264)
> changes: `hwk → /pseudonymous`, `jwks_uri → /identified`, `jkt-jwt → /anchored`
> (all on Profile `:5000`), and the `jwt` default path becomes `/events` on
> Calendar `:5001`. The base resource URL passed on the CLI moves from `:5000`
> (WhoAmI) to `:5001` (Calendar) for three-party examples, while identity
> examples target `:5000` (Profile).

### MissionAgent (10-step lifecycle)

| Step | Today: server · endpoint · scope | Aria: server · endpoint · scope |
|---|---|---|
| 1 · AP enrol | AP `:5301` | unchanged |
| 2 · Propose mission | PS `/mission` | unchanged (mission intent now worded as trip planning) |
| 3 · Access mission-aware resource | WhoAmI `/jwt/mission` · `whoami` (silent) | **Trips** `/trips` · `trips.read` (silent) |
| 4 · Access again (prior consent) | WhoAmI `/jwt/mission` · `whoami` (silent) | **Trips** `/trips` · `trips.read` (silent) |
| 5 · Access elevated scope | WhoAmI `/jwt/mission/elevated` · `whoami:elevated_scope` (prompt) | **Trips** `/trips/book` · `trips.book` (prompt) |
| 6–10 · tool permission / audit / question / complete | PS endpoints | unchanged |

> Default mission-approved set [MissionAgent/Program.cs#L48-L49](../../../samples/MissionAgent/Program.cs#L48-L49)
> changes from `{ "whoami" }` to `{ "trips.read" }`; the elevated override
> `--mission-approved whoami:elevated_scope` becomes
> `--mission-approved trips.book`.

## Things every option must preserve

- **Well-known endpoints** (`/.well-known/aauth-resource.json`,
  `/.well-known/jwks.json`) served before verification on each new server.
- **Fail-closed trusted-issuer** config (`AAuth:TrustedPersonServers` for
  three-party; trusted AS for four-party).
- **MissionAware challenge** behavior for the mission server (mission object
  round-trip: approver + s256).
- **Step-up scope** and **RBAC role** demos somewhere (whether merged onto the
  core server or split — see open questions).
- **Call-chaining**: Orchestrator → core user-data server still works
  end-to-end (downstream path + scope updated).
- **Live interop**: `LiveWhoAmITest` targets the external `whoami.aauth.dev`,
  which this refactor does **not** control. **Decision: out of scope** — it is
  left entirely unchanged (keeps its `whoami` paths and external endpoints).
- **e2e/playwright assertions** that check `scope == ['whoami']` and specific
  paths must be updated in lockstep (GuidedTour + SampleApp specs).

> **Update scope (2026-06): no backward compatibility.** The old `whoami` scope
> family and `/jwt*` paths are **replaced outright** — no deprecated aliases.
> Every reference must be migrated to the Aria taxonomy in one pass, including:
> all sample code (`Program.cs`, `.razor` pages, `.csproj`, `appsettings.json`),
> all docs under `docs/` and every `README.md`, the GuidedTour **code snippets**
> ([CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs)) and all
> **on-screen text / step descriptions** in GuidedTour and SampleApp, the
> Makefile targets, the Keycloak realm + stub policy, MockPersonServer consent
> seeding, and all e2e/playwright specs. Only `LiveWhoAmITest` is exempt (see
> above).

## Gaps & open questions

1. **Server count.** _Resolved: 4 servers_ (Profile, Calendar, Trips, Wallet),
   one per access mode. Step-up (`/events/write`) and RBAC (`/events/admin`)
   stay as extra endpoints on Calendar since they are scope tiers of one
   product.
2. **Ports.** _Resolved: `:5000`–`:5003`_ — Profile `:5000`, Calendar `:5001`,
   Trips `:5002`, Wallet `:5003`. Clear of PS `:5100`, Orchestrator `:5200`,
   SampleApp `:5240`, AP `:5301`, GuidedTour `:5400`, AS `:5500`. The documented
   port map (Makefile, e2e config, READMEs) is updated to match.
3. **Single multi-project vs shared library.** _Resolved: no shared library._
   The four servers are standalone copy-paste `Program.cs` templates; the SDK
   already carries the reusable plumbing.
4. **Naming of the SDK marker type.** _Resolved._ Each server gets a
   `WebApplicationFactory` marker matching its root namespace: `Profile.Entry`,
   `Calendar.Entry`, `Trips.Entry`, `Wallet.Entry` (replacing `WhoAmI.Entry`).
   Test fixtures update accordingly.
5. **LiveWhoAmITest scope.** _Resolved: out of scope._ It keeps pointing at the
   public `whoami.aauth.dev` and is left unchanged; it cannot adopt local
   renamed scopes.
6. **Federated/Keycloak realm.** _Resolved._ `keycloak/realm-aauth.json` and
   `StubAccessPolicy` are re-modeled for the Wallet: scopes `wallet.read` (any
   user) + `wallet.charge` (role-gated), role `wallet.payer`, resource name
   `wallet`. The two existing users keep their behavior — `demo`/`demo` gets
   `wallet.payer` (can charge), `guest`/`guest` does not (read-only). This is a
   1:1 rename of today's `whoami`/`whoami:admin`/`whoami-admin` triple, now with
   a federated endpoint (`/wallet/charge`) that actually exercises it.
7. **MockPersonServer consent seeding.** _Mechanical (follows #2 + #6)._
   Consent + roles are seeded per resource **origin** and scope. Update the
   seed/admin-consent payloads and the e2e consent helper for the new origins
   (`:5001` Calendar, `:5002` Trips, `:5003` Wallet) and scope names
   (`calendar.read`, `calendar.write`, `trips.read`, `trips.book`, etc.) and the
   `calendar.owner` role.
8. **Backward-compatible aliases?** _Resolved: no._ The old `whoami` scope and
   `/jwt*` paths are replaced outright with no deprecated aliases; every
   in-repo reference (code, docs, code snippets, GuidedTour/SampleApp UI text,
   tests, Makefile) is migrated in one pass. `LiveWhoAmITest` is the only
   exemption.

## Follow-up — narrative coherence pass (2026-06-09)

> **Update (2026-06):** After the split landed and the "What Aria is trying to
> do" narratives were added (Phase 11), two narrative inconsistencies surfaced
> that a find/replace migration could not catch. Recorded here as facts; the
> concrete steps live in Phases 12–16 of the plan.

### Finding A — "Orchestrator" does not fit the Aria narrative

The intermediate call-chain service (`samples/Orchestrator`, `:5200`, scope
`orchestrate`, identity `aauth:orchestrator@localhost:5200`) is described in
generic middleware terms. Functionally it is the service Aria *asks* to arrange
something with a downstream provider on the user's behalf — exactly a travel
**concierge**. Decision: rename to **Concierge** across samples, config, tests,
and docs. The SDK (`src/AAuth`) has **zero** `orchestrat*` references (only two
incidental doc-comment mentions), so this is samples-only. Blast radius ≈ 235
references; the only non-cosmetic identifiers are the demo-defined scope
(`orchestrate`→`concierge`) and agent id (`aauth:orchestrator@…`→
`aauth:concierge@…`) — neither is an SDK constant. Port `:5200` is kept (infra,
no narrative value in changing it). See the per-category inventory captured by
the research sweep saved alongside this initiative.

### Finding B — the Mission demo's example is off-theme and self-contradictory

The mission narrative is about an **email inbox** ("Keep the inbox under control
for an hour"; tools `summarize`, `send_email`, `delete_inbox`) but the scopes it
actually requests are `trips.read` / `trips.book`. A new reader sees an inbox
mission suddenly read and book **trips**. Decision: re-theme the example to a
single coherent travel story — mission "Plan my weekend trip to Seattle." —
keeping the exact pedagogy:

| Gate | Old demo string | New demo string | Teaches (unchanged) |
|---|---|---|---|
| 2 in-scope scope (SILENT) | `trips.read` | `trips.read` *(kept — protocol)* | scope fits intent → silent |
| 3 out-of-scope scope (PROMPT) | `trips.book` | `trips.book` *(kept — protocol)* | booking ≠ "plan" → prompts |
| 4 pre-approved tool (SILENT, local) | `send_email` | `add_to_calendar` | declared tool → no PS call |
| 4′ pre-approved tool #2 | `summarize` | `compare_options` | declared tool list |
| 5 non-approved tool (PROMPT) | `delete_inbox` | `cancel_booking` | undeclared, destructive → asks |

Tool names are **pure demo strings** (the SDK has zero references to them; the
conformance test `GovernanceServerTests` already uses `"SendEmail"`/`"Send the
itinerary"` independently). Scope names `trips.read`/`trips.book` are
protocol-bound and **stay**. Several mission scope *descriptions* are stale
holdovers from `whoami` (e.g. `trips.read` shown as "See basic profile
information") and are corrected in the same pass.

## Sources

- [samples/WhoAmI/Program.cs](../../../samples/WhoAmI/Program.cs) — current
  nine-path server.
- [samples/README.md](../../../samples/README.md) — endpoint matrix.
- [docs/getting-started.md](../../../docs/getting-started.md) — four-access-mode
  taxonomy.
- Sample + doc references enumerated in the inventory tables above.
