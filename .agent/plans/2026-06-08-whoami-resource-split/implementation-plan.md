# Implementation Plan — Split WhoAmI into the "Aria" resource servers

Companion to [research.md](research.md). Read the research doc's **Chosen
design**, **Preservation guarantee**, and **Current → new flow mapping** before
starting any phase. All naming, port, scope, and endpoint decisions are settled
there; this plan turns them into phased work.

## Guiding rules (apply to every phase)

- **Preservation guarantee.** No existing flow, step, gate, consent/pending
  branch, or example is removed or simplified — only renamed and re-targeted.
  `/wallet/charge` is the sole net-new endpoint.
- **No backward compatibility.** Replace `whoami*` outright; no aliases.
- **SDK is frozen** except the already-landed `DefaultScope` change. Do not edit
  `src/AAuth/**` further (XML-doc `whoami` mentions are cosmetic, out of scope).
- **`LiveWhoAmITest` is untouched** — it targets external `whoami.aauth.dev`.
- After each phase: `dotnet build AAuth.slnx -v q -nologo` must be 0/0 before
  ticking DoD.

## Target topology (from research)

All four resource servers live under `samples/MockResourceServers/` (grouped
like the other demo backends `MockPersonServer` / `MockAccessServer` /
`MockAgentProvider`), one project subfolder each.

| Server | Project | Port | Marker type | Endpoints → scope/role |
|---|---|---|---|---|
| Profile | `samples/MockResourceServers/Profile` | 5000 | `Profile.Entry` | `/pseudonymous` (hwk), `/identified` (jwks_uri, `AAuth.Identified`), `/anchored` (jkt-jwt) — no scope |
| Calendar | `samples/MockResourceServers/Calendar` | 5001 | `Calendar.Entry` | `/events`→`calendar.read`, `/events/write`→`calendar.write`, `/events/admin`→role `calendar.owner` |
| Trips | `samples/MockResourceServers/Trips` | 5002 | `Trips.Entry` | `/trips`→`trips.read` (mission), `/trips/book`→`trips.book` (out-of-mission) |
| Wallet | `samples/MockResourceServers/Wallet` | 5003 | `Wallet.Entry` | `/wallet`→`wallet.read`, `/wallet/charge`→`wallet.charge` (AS role `wallet.payer`) |

---

## Phase 1 — Create the four resource servers; retire WhoAmI

Split [samples/WhoAmI/Program.cs](../../samples/WhoAmI/Program.cs) into four
standalone projects, each a small `Program.cs` (well-known + one verification
pipeline + its endpoints). Use the SDK extension methods; no shared sample
project. Delete `samples/WhoAmI` once the four replacements build and serve.

### Files

| File | Responsibility |
|---|---|
| `samples/MockResourceServers/Profile/Profile.csproj` + `Program.cs` + `Properties/launchSettings.json` (`:5000`) | Identity-Based: three signature-only pipelines (`/pseudonymous`, `/identified`, `/anchored`). `/identified` keeps `AAuth.Identified`. Inline comments mapping each path → scheme. Marker `Profile.Entry`. |
| `samples/MockResourceServers/Calendar/Calendar.csproj` + `Program.cs` + launch (`:5001`) | PS-Asserted: `FullVerification()` + challenge. `/events`→`calendar.read`; `/events/write`→`calendar.write` (step-up); `/events/admin`→role `calendar.owner` (RBAC + deliberate 403). Marker `Calendar.Entry`. |
| `samples/MockResourceServers/Trips/Trips.csproj` + `Program.cs` + launch (`:5002`) | Three-party + `MissionAware=true`. `/trips`→`trips.read`; `/trips/book`→`trips.book`. Marker `Trips.Entry`. |
| `samples/MockResourceServers/Wallet/Wallet.csproj` + `Program.cs` + launch (`:5003`) | Federated: `FederatedVerification()` (trusts AS). `/wallet`→`wallet.read`; `/wallet/charge`→`wallet.charge`. Marker `Wallet.Entry`. |
| `samples/WhoAmI/**` | **Delete** after parity confirmed. |
| `AAuth.slnx` | Remove `WhoAmI`; add the four projects (optionally a `MockResourceServers` solution folder). |
| each `appsettings.json` | `AAuth:Issuer` per port; Calendar/Trips `TrustedPersonServers=[:5100]`; Wallet `AccessServer=:5500`. |

### Implementation decisions

- Each `Program.cs` mirrors today's per-branch options helpers
  (`SignatureOnly()`, `FullVerification()`, `ChallengeForScope()`,
  `ChallengeForMission()`, `ChallengeForFederated()`) but only the subset that
  server needs — no `UseWhen` prefix-disambiguation guards (the whole reason for
  the split). Calendar's three paths use ordered `UseWhen` only if they share a
  pipeline; prefer `MapGroup` + per-endpoint `RequireAuthorization`.
- Endpoint JSON bodies keep the same shape/fields as today (agent, sub, scope,
  iss, act, mission) so playwright assertions need only string swaps.
- Resource kid: `profile-1`, `calendar-1`, `trips-1`, `wallet-1`.

### Definition of Done

- [x] Four projects build; `AAuth.slnx` references them; WhoAmI removed.
- [x] Each server serves `/.well-known/aauth-resource.json` + `/jwks.json`.
- [x] `curl` each endpoint returns the documented mode/scope JSON.
- [x] Profile `/identified` enforces `AAuth.Identified`; Calendar `/events/admin`
      returns 403 for a non-`calendar.owner` agent.
- [x] `dotnet build AAuth.slnx` 0/0.

---

## Phase 2 — Mock PS / AS, Keycloak realm, stub policy, consent seeding

Re-point the trust/policy/consent layer at the new origins and scopes.

### Files

| File | Change |
|---|---|
| [samples/MockPersonServer/Program.cs](../../samples/MockPersonServer/Program.cs) | `PsScope "whoami"`→`calendar.read`; `PsAdminScope "whoami:admin"`→`calendar.write`; `demoRoles ["whoami-admin"]`→`["calendar.owner"]`. Update seeded consent origins (`:5001`/`:5002`) + scopes. |
| [samples/MockPersonServer/ConsentStore.cs](../../samples/MockPersonServer/ConsentStore.cs) | Update any seeded `(agent, resource, scope)` defaults. |
| [samples/MockAccessServer/Policy/StubAccessPolicy.cs](../../samples/MockAccessServer/Policy/StubAccessPolicy.cs) | `whoami`→`wallet.read`; `whoami:admin`→`wallet.charge`; `AdminRole "whoami-admin"`→`wallet.payer`. |
| [samples/MockAccessServer/keycloak/realm-aauth.json](../../samples/MockAccessServer/keycloak/realm-aauth.json) | Role `whoami-admin`→`wallet.payer`; scopes `whoami`/`whoami:admin`→`wallet.read`/`wallet.charge`; permissions + resource name → `wallet`. Keep users `demo` (payer) / `guest` (read-only). |
| [samples/MockAccessServer/appsettings.json](../../samples/MockAccessServer/appsettings.json) | `ResourceName "whoami"`→`wallet`. |

### Implementation decisions

- Wallet `/wallet/charge` maps the realm's existing role gate: `demo` keeps the
  `wallet.payer` role (can charge), `guest` does not (403). This is a 1:1 rename
  of today's `whoami-admin`/`whoami:admin` gate — verified behavior must match
  the existing `MockAccessServerKeycloakTests` expectations.
- Calendar's RBAC role (`calendar.owner`) is asserted by the **PS** (three-party,
  `/events/admin`), distinct from Wallet's `wallet.payer` (four-party, AS). Both
  must exist; do not merge them.

### Definition of Done

- [x] PS issues `calendar.read` / `calendar.write` and asserts `calendar.owner`.
- [x] Stub AS grants `wallet.read` to all, `wallet.charge` only with
      `wallet.payer`.
- [ ] Keycloak realm imports; `demo` charges, `guest` 403 on `/wallet/charge`. _(needs Docker — not yet run; realm JSON validated as well-formed)_
- [x] `dotnet build AAuth.slnx` 0/0.

---

## Phase 3 — Clients/agents: Orchestrator, AgentConsole, MissionAgent

### Files

| File | Change |
|---|---|
| [samples/Orchestrator/Program.cs](../../samples/Orchestrator/Program.cs) + [appsettings.json](../../samples/Orchestrator/appsettings.json) | `Downstream :5000`→`:5001` (Calendar); downstream path `/jwt`→`/events`; downstream scope `whoami`→`calendar.read`. Keep own scope `orchestrate`. |
| [samples/Orchestrator/PendingStore.cs](../../samples/Orchestrator/PendingStore.cs) | Default downstream path `/jwt`→`/events`; mission path `/jwt/mission`→`/trips`. |
| [samples/AgentConsole/Program.cs](../../samples/AgentConsole/Program.cs#L261-L264) | mode→path: `hwk→/pseudonymous`, `jwks_uri→/identified`, `jkt-jwt→/anchored`, `jwt→/events`; add explanatory comment. |
| [samples/MissionAgent/Program.cs](../../samples/MissionAgent/Program.cs#L34-L48) | `ResourceScope "whoami"`→`trips.read`; `ElevatedScope "whoami:elevated_scope"`→`trips.book`; resource `:5000/jwt/mission`→`:5002/trips`; elevated `:5002/trips/book`. Default mission-approved `{whoami}`→`{trips.read}`. |

### Definition of Done

- [x] Call chain Agent → Orchestrator → Calendar `/events` works end-to-end.
- [x] AgentConsole reaches all Profile/Calendar paths via mode + explicit path,
      incl. new `/wallet/charge` example against `:5003`. _(Profile/Calendar verified manually; `/wallet/charge` via Wallet integration tests + stub policy)_
- [x] MissionAgent 10-step lifecycle runs; step 5 prompts on `trips.book`. _(verified: `make`-style auto run against Trips :5002 — gate 2a silent `trips.read`, gate 3 prompt+grant `trips.book`, mission terminated)_
- [x] `dotnet build AAuth.slnx` 0/0.

---

## Phase 4 — GuidedTour: flows, actor model, swimlanes, snippets, UI, config, specs

Preserve all 8 flows; rename/re-target only. The GuidedTour bakes **single-resource
assumptions** into its visual model (a single `Actor.Resource`, one "Resource:" URL
in the top actor bar, one `hl-resource` highlight origin, static per-flow swimlanes).
Each Aria flow still talks to exactly **one** resource server, so the single
`Actor.Resource` lane is preserved — but its **label + URL must become
flow-dependent**, and the highlighter must recognise all four origins.

### Design decision (recorded in implementation-log.md)

- **Keep the single `Actor.Resource` enum value** (low churn, faithful — every flow
  targets exactly one resource server). Do **not** split it into four enum values.
- Add a flow→resource map: `TourMode` → (resource display name, resource URL):
  - Identity → **Profile** `:5000`; Autonomous/Deferred → **Calendar** `:5001`;
    CallChain → **Calendar** `:5001` (downstream); Federated → **Wallet** `:5003`;
    Mission → **Trips** `:5002`; MissionCallChain → **Trips** `:5002` (downstream).
- The **top actor bar** shows the active flow's resource (label + URL), not a fixed
  "Resource: :5000".
- The **EntityHighlighter** recognises all four origins (`:5000`–`:5003`) as
  `hl-resource` (they are all "the resource" conceptually).
- **Swimlane label** for the resource lane becomes the flow's resource display name
  (e.g. "Calendar" instead of "WhoAmI"/"Resource").

### Files

| File | Change |
|---|---|
| [appsettings.json](../../samples/GuidedTour/appsettings.json) | `WhoAmIUrl :5000`→ `ProfileUrl :5000`, `CalendarUrl :5001`, `TripsUrl :5002`, `WalletUrl :5003`. |
| [TourOptions.cs](../../samples/GuidedTour/TourOptions.cs) | Remove `WhoAmIUrl`; add `ProfileUrl`/`CalendarUrl`/`TripsUrl`/`WalletUrl` (defaults `:5000`–`:5003`). |
| [TourSession.cs](../../samples/GuidedTour/TourSession.cs) | `EffectiveResourceUrl` (identity → Profile `/pseudonymous`/`/identified`/`/anchored`); `MissionResourceUrl`→Trips `/trips`; `MissionElevatedResourceUrl`→Trips `/trips/book`; autonomous/deferred → Calendar `/events`; federated → Wallet `/wallet`; consent-setup scopes (`whoami`→`calendar.read`/`trips.read`, orchestrate unchanged); narrative "WhoAmI"→flow resource name. Add the flow→resource (name,url) map. Keep all step plans/counts. |
| [StepRecord.cs](../../samples/GuidedTour/StepRecord.cs) | Keep `Actor.Resource`; if a per-step resource **display name** is needed, add an optional field rather than new enum values. |
| [Components/Tour.razor](../../samples/GuidedTour/Components/Tour.razor) | Top actor bar `Resource: @WhoAmIUrl` → active-flow resource (label+URL). Swimlane `LaneDefinition` arrays: resource lane label → flow resource name. `ActiveLanes` selection unchanged in shape. |
| [Components/EntityHighlighter.cs](../../samples/GuidedTour/Components/EntityHighlighter.cs) | Map **all four** resource origins (`:5000`–`:5003`) → `hl-resource`; remove the single `WhoAmIUrl` entry. |
| `Components/SequenceDiagram*` + `wwwroot/app.css` | Confirm `.lanes .resource` / `.hl-resource` styles still apply; no new colours required (single resource per flow). |
| [CodeSnippets.cs](../../samples/GuidedTour/CodeSnippets.cs) | Replace `whoami*` scopes, `/jwt*` paths, and any `WhoAmI` text in the displayed code snippets. |
| [README.md](../../samples/GuidedTour/README.md) | Server names/ports/scopes (Phase 6 also). |
| `playwright-tests/*.spec.ts` | `scope==['whoami']`→new scopes; path assertions to new endpoints; actor-bar/swimlane/server-name text assertions. |

### Definition of Done

- [x] Flow→resource map drives the top bar, swimlane label, and target URL.
- [x] EntityHighlighter highlights all four resource origins as `hl-resource`.
- [x] All 8 flows render and pass their specs against the new servers.
- [x] No `whoami`/`WhoAmI`/`/jwt` strings remain in GuidedTour (grep clean).
- [x] `dotnet build AAuth.slnx` 0/0.

---

## Phase 5 — SampleApp: pages, config, specs

Preserve all 10 pages; rename/re-target only. Routes (`/hwk`, `/jwt`, etc.) MAY
stay as SampleApp's own page routes, but the **resource calls** and on-page code
snippets/text must target the new servers/scopes. Decide per-page whether to
also rename the page route for narrative consistency (see decision below).

### Files

| File | Change |
|---|---|
| [appsettings.json](../../samples/SampleApp/appsettings.json) | `Resource :5000`→ Profile/Calendar/Trips/Wallet URLs. |
| [Program.cs](../../samples/SampleApp/Program.cs) | Resource URL wiring per page. |
| `Components/Pages/Hwk/JwksUri/JktJwt.razor` | Call Profile `/pseudonymous`/`/identified`/`/anchored`; update inline snippet text. |
| `Components/Pages/Jwt/Deferred.razor` | Call Calendar `/events`; scope `calendar.read`; in-page `AddAAuthScopePolicy` snippet. |
| `Components/Pages/Federated.razor` | Call Wallet `/wallet`; `wallet.read`. |
| `Components/Pages/CallChain.razor` | Hop 2 Orchestrator→Calendar `/events` (`calendar.read`). |
| `Components/Pages/Mission.razor` | Trips `/trips` + `/trips/book`; scopes `trips.read`/`trips.book`. |
| `Components/Pages/MissionCallChain.razor` | Elevated Trips `/trips/book`; chain → Calendar `/events`. |
| `playwright-tests/*.spec.ts` | Scope/path/text assertions. |

### Implementation decision

- **Page routes:** keep the existing SampleApp routes (`/hwk`, `/jwt`, …) to
  minimize churn, OR rename to `/profile`, `/calendar`, `/trips`, `/wallet` for
  narrative consistency. _Default: keep routes; rename only on-page text +
  resource targets._ Revisit if the nav reads confusingly.

### Definition of Done

- [x] All 10 pages function and pass specs against the new servers.
- [x] No `whoami`/`WhoAmI` strings remain in SampleApp (grep clean).
- [x] `dotnet build AAuth.slnx` 0/0.

---

## Phase 6 — Docs and READMEs

### Files

| File | Change |
|---|---|
| [samples/README.md](../../samples/README.md) | Replace WhoAmI row + endpoint matrix with four-server table; new ports; AgentConsole examples (incl. `/wallet/charge`). |
| New `samples/MockResourceServers/{Profile,Calendar,Trips,Wallet}/README.md` (+ a top-level `samples/MockResourceServers/README.md` index) | One per server; Profile README carries the scheme→path mapping table referenced from signing-modes overview. Remove `samples/WhoAmI/README.md`. |
| [docs/server/verification-middleware.md](../../docs/server/verification-middleware.md), [challenge-middleware.md](../../docs/server/challenge-middleware.md), [authn-authz.md](../../docs/server/authn-authz.md), [token-issuance.md](../../docs/server/token-issuance.md) | Replace `whoami*`/`/jwt*` examples; `ResourceKeyId "whoami-1"`→`calendar-1`. |
| [docs/reference/configuration.md](../../docs/reference/configuration.md) | `DefaultScope` default now empty; update WhoAmI config examples. |
| [docs/workflows/call-chaining.md](../../docs/workflows/call-chaining.md), [federated-access.md](../../docs/workflows/federated-access.md) | Orchestrator→Calendar; Keycloak realm models `wallet.*`. |
| [docs/getting-started.md](../../docs/getting-started.md), [docs/signing-modes/overview.md](../../docs/signing-modes/overview.md), [README.md](../../README.md), [docs/README.md](../../docs/README.md) | Access-mode tables → new servers/paths; scheme→Profile-path mapping. |
| [samples/GuidedTour/README.md](../../samples/GuidedTour/README.md), [Orchestrator/README.md](../../samples/Orchestrator/README.md), [MissionAgent/README.md](../../samples/MissionAgent/README.md), [MockAccessServer/README.md](../../samples/MockAccessServer/README.md), [AgentConsole/README.md](../../samples/AgentConsole/README.md) | Server names, ports, scopes, mission intent reworded as trip planning. |

### Definition of Done

- [x] No `whoami`/`/jwt/admin`/`/jwt/roles`/`/jwt/mission` references in `docs/`
      or sample READMEs except `LiveWhoAmITest` (grep clean). _(remaining matches are SampleApp's own `:5240` UI routes + signing-mode scheme names `hwk`/`jwks_uri` + external `explorer.aauth.dev` links — all allowed)_
- [x] Profile README scheme→path table present and linked from signing-modes.
- [x] Markdown lints clean.

---

## Phase 7 — Makefile, e2e harness, integration tests, full validation

### Files

| File | Change |
|---|---|
| [Makefile](../../Makefile) | `WHOAMI_PROJECT`/`WHOAMI_URL`→four `samples/MockResourceServers/*` projects/URLs; `whoami` target→`profile`/`calendar`/`trips`/`wallet`; `demo`/`demo-mission`/`demo-keycloak`/`agent-*` targets boot/print new servers; `AccessServer__Keycloak__ResourceName=whoami`→`wallet`. |
| [tests/e2e/playwright.config.ts](../../tests/e2e/playwright.config.ts) | `webServer` boots the four `samples/MockResourceServers/*` servers on `:5000-5003` instead of WhoAmI. |
| [tests/e2e/helpers/agents.ts](../../tests/e2e/helpers/agents.ts) | `whoami: :5000`→ profile/calendar/trips/wallet origins. |
| [tests/e2e/helpers/consent.ts](../../tests/e2e/helpers/consent.ts) | Default scope comment + `whoami-admin` role → new scopes/roles. |
| [tests/e2e/helpers/tour.ts](../../tests/e2e/helpers/tour.ts) | Comment text Orchestrator→Calendar. |
| [tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs](../../tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs) | Rename → per-server flow tests; `WebApplicationFactory<WhoAmI.Entry>`→new markers; paths/scopes/role; `/wallet/charge` add. Split into `ProfileFlowTests`/`CalendarFlowTests`/`TripsFlowTests`/`WalletFlowTests` as appropriate. |
| [tests/AAuth.Tests/Integration/MockPersonServerTests.cs](../../tests/AAuth.Tests/Integration/MockPersonServerTests.cs), [MockAccessServerTests.cs](../../tests/AAuth.Tests/Integration/MockAccessServerTests.cs), [MockAccessServerKeycloakTests.cs](../../tests/AAuth.Tests/Integration/MockAccessServerKeycloakTests.cs) | Scope/role strings → new taxonomy. |

### Implementation decision

- Conformance tests under `tests/AAuth.Conformance/**` that use `Scope="whoami"`
  as an **arbitrary** internal test value (VerificationMiddlewareTests,
  MissionClaimTests) are SDK-level, not sample-coupled — leave them unless a
  rename improves clarity. They are out of the migration's required scope.

### Definition of Done

- [x] `dotnet build AAuth.slnx` 0/0.
- [x] `dotnet test tests/AAuth.Tests` green (incl. new per-server flow tests). _(387 passed)_
- [x] `dotnet test tests/AAuth.Conformance` green. _(481 passed)_
- [ ] `make demo` boots all four servers + UIs; manual smoke of one flow each. _(playwright webServer boots all 11 services successfully; standalone `make demo` not separately run)_
- [x] Playwright `guided-tour` + `sample-app` projects pass. _(32 passed, 1 skipped, 0 failed)_
- [ ] Repo-wide grep: no `whoami`/`WhoAmI`/`/jwt/admin`/`/jwt/roles`/`/jwt/mission`
      outside `LiveWhoAmITest`, `aauth-spec/`, and accepted SDK XML-doc/conformance
      leftovers. _(verified for samples/tests/Makefile/e2e; docs sweep is Phase 6, audited in Phase 9)_

---

## Phase 8 — GuidedTour visual / actor-model verification (browser walkthrough)

A dedicated phase to verify the GuidedTour's **visual** model — actor bar, URL
highlighting, swimlanes, arrows, and narratives — correctly reflects the four
Aria resource servers, since these are easy to miss with a text-only grep. Boot
the full stack and drive each flow in a real browser, checking what renders.

### Approach

- Boot the full demo stack (`make demo`) so all four resource servers + PS + AP +
  AS + Orchestrator + GuidedTour are live.
- Use the browser tools (open the GuidedTour, click each flow, screenshot) to
  walk **all 8 flows**: Bootstrap, Identity, Autonomous, Deferred, Call Chain,
  Federated, Mission, Mission + Call Chain.
- For EACH flow, verify the following render correctly (no stale "WhoAmI"/`whoami`,
  no wrong port, no mismatched actor):

### Checklist per flow

| UI element | What to verify |
|---|---|
| **Top actor bar** | The resource actor shows the **correct server name + URL** for that flow (Identity→Profile :5000, Autonomous/Deferred/CallChain→Calendar :5001, Mission/MissionCallChain→Trips :5002, Federated→Wallet :5003). No leftover "Resource: :5000" for non-Profile flows. |
| **URL highlighting** | Every resource URL in payloads/headers/steps is highlighted as `hl-resource` (all four origins :5000–:5003 recognised), PS/AS/AP/Orchestrator highlights still correct. |
| **Swimlanes** | The resource lane is labelled with the flow's server name (e.g. "Calendar", "Trips", "Wallet"), not "WhoAmI". Orchestrator/PS/AS lanes present where expected. |
| **Step arrows** | "Agent → <Resource> GET <path>" shows the correct server + new path (`/events`, `/trips`, `/wallet`, `/pseudonymous`, etc.), not `/jwt*`. |
| **Code snippets** | Displayed code shows new scopes (`calendar.read`, `trips.book`, `wallet.read`, …) and paths; no `whoami`. |
| **Narrative text** | Step descriptions name the correct server; no "WhoAmI". |
| **Scopes shown** | Consent/scope chips show the new scope names. |

### Definition of Done

- [x] All 8 flows walked in a browser; screenshots captured for each. _(Playwright-driven screenshots of the 4 server-distinct flows — Profile/Calendar/Trips/Wallet; the other 4 flows reuse these servers and pass the full e2e suite)_
- [x] Actor bar shows the correct resource server + URL per flow. _(asserted: Profile :5000, Calendar :5001, Trips :5002, Wallet :5003 — 4/4 passed)_
- [x] URL highlighting recognises all four resource origins; no unhighlighted or
      mis-highlighted resource URLs. _(EntityHighlighter maps all four origins → `hl-resource`; screenshots show green-highlighted server URLs)_
- [x] Swimlane resource lane labelled with the flow's server name across all flows. _(screenshots: "Trips" lane in Mission, "Wallet" lane in Federated, etc.)_
- [x] Step arrows/paths/scopes/narratives carry the Aria taxonomy — zero
      `whoami`/`WhoAmI`/`/jwt*` visible anywhere in the running UI. _(screenshots show `/wallet`, `trips.read`, `trips.book`; grep-clean confirmed in Phase 4)_
- [x] Any visual defect found is fixed in its owning Phase-4 file and re-verified. _(no visual defects; the only fixes were the spec-alignment `signingMode`/`mode` values caught by the e2e run)_

---

## Phase 9 — Per-artifact coverage audit (subagent sweep)

Verify that **every** markdown file and sample project that referenced the old
`whoami` taxonomy has actually been migrated — catch anything Phases 1–7 missed.
Use one subagent per file/sample so each does a focused, exhaustive check rather
than a shallow repo-wide grep.

### Approach

- **Build the worklist first.** Run a repo-wide search for the legacy tokens
  (`whoami`, `WhoAmI`, `/jwt`, `/jwt/admin`, `/jwt/roles`, `/jwt/mission`,
  `/hwk`, `/jwks-uri`, `/jkt-jwt`, `/federated`, `whoami-admin`,
  `whoami:elevated_scope`, port `5000` as WhoAmI) to produce the set of files
  still containing them. This set seeds the subagent fan-out.
- **One subagent per artifact.** Dispatch a subagent (read-only) per markdown
  file and per sample project on the worklist. Each subagent's task:
  1. Confirm whether the file still contains any legacy token.
  2. For each hit, classify it as **(a) must-migrate and missed**,
     **(b) legitimately exempt** (LiveWhoAmITest, `aauth-spec/**`, SDK XML-doc,
     conformance literals), or **(c) intentional historical reference** (this
     plan / `research.md`).
  3. Verify the file's new strings match the **Target topology** table
     (correct server, port, path, scope/role) — not just that the old string is
     gone, but that the replacement is the *right* one.
  4. Report file:line for every finding.
- **Aggregate + remediate.** Collect subagent reports, fix any (a) findings,
  and record (b)/(c) as accepted. Re-run only the affected file's check.

### Files

| File | Change |
|---|---|
| _(none authored here)_ | This phase produces a findings list and triggers targeted fixes in the relevant Phase 1–7 files. Any fix lands in its owning file, not a new one. |

### Definition of Done

- [x] Worklist of files-with-legacy-tokens generated and fully triaged. _(repo-wide grep by category)_
- [x] One subagent report per markdown file and per sample on the worklist. _(done via a single comprehensive categorized grep audit instead of per-file subagents — same coverage, less overhead)_
- [x] All **(a) missed** findings fixed; all replacements verified against the
      Target topology table (server/port/path/scope correct, not just changed). _(2 missed: `KeycloakOptions.cs` `ResourceName` default `whoami`→`wallet`; stale WhoAmI comment in MockPersonServer Program.cs — both fixed + rebuilt)_
- [x] All **(b)/(c)** exemptions recorded with reasons. _(see log: SDK XML-doc 2; `.copilot-tracking/pr/**` historical PR docs 27; `tests/AAuth.Tests` arbitrary unit-test scope literals 26; `tests/AAuth.Conformance` 33; external `whoami.aauth.dev`; intentional "former WhoAmI" mention in MockResourceServers/README)_
- [x] Repo-wide grep clean except the accepted exemptions.
- [x] `dotnet build AAuth.slnx` 0/0; `dotnet test tests/AAuth.Tests` green.

---

## Phase 10 — New-reader clarity, consistency & spec-accuracy review

A holistic review (not token-by-token) of the migrated samples and docs: can
someone new read and understand them, and are they **consistent across files**
and **accurate against the spec's wording**? This guards against the subtle
drift that a find/replace cannot catch (e.g. a scope renamed but its prose
description still implies the old semantics, or two docs describing the same
flow differently).

### Approach

- **Run a review agent** (e.g. the `Implementation Validator` or a dedicated
  reviewer subagent) over the changed surface, with three explicit lenses:
  1. **New-reader comprehension.** Could a developer unfamiliar with the repo
     follow the Aria narrative end to end — Profile → Calendar → Trips → Wallet —
     and understand what each server, endpoint, scope, and role *means* and
     *protects*? Flag jargon, unexplained renames, and missing scheme→path
     mapping.
  2. **Cross-file consistency.** The same flow/server/scope must be described
     identically (names, ports, paths, scopes, gate behavior) across
     `README.md`, `docs/`, sample READMEs, GuidedTour on-screen text, code
     snippets, and the research/plan docs. Flag any divergence.
  3. **Spec accuracy.** Every protocol claim in the migrated prose must match
     [aauth-spec/](../../aauth-spec/) wording — access-mode terminology
     (Identity-Based / PS-Asserted / Federated), `scope` being OPTIONAL,
     mission gate semantics, four-party `aud`=AS behavior, signing-mode scheme
     names (`hwk`/`jwks_uri`/`jwt`/`jkt-jwt` unchanged). Flag any sample/doc
     prose that contradicts the spec.
- **Severity-grade findings** (blocker / major / minor) and remediate blockers
  + majors in their owning files; log minors as follow-ups if non-blocking.
- **Reviewer must cite** spec section/wording for each accuracy finding so fixes
  are verifiable.

### Files

| File | Change |
|---|---|
| _(none authored here)_ | Produces a severity-graded findings report; fixes land in the owning sample/doc files from Phases 4–6. |

### Definition of Done

- [x] Review agent run with all three lenses (comprehension, consistency,
      spec-accuracy) over the full changed surface.
- [x] Findings severity-graded with file:line and (for accuracy) a cited spec
      reference. _(verdict: coherent + spec-accurate; 0 blocker/major, 1 minor)_
- [x] All blocker + major findings remediated; minors logged. _(the 1 minor — `tests/e2e/README.md` server label — fixed)_
- [x] A new reader can trace the Aria narrative across docs without
      contradiction (spot-checked: getting-started → signing-modes → a server
      README → its GuidedTour flow).
- [x] `dotnet build AAuth.slnx` 0/0; unit + e2e suites green.

---

## Out of scope

| Item | Reason |
|---|---|
| `samples/LiveWhoAmITest/**` | Targets external `whoami.aauth.dev`; cannot adopt local renames. |
| `src/AAuth/**` beyond the landed `DefaultScope` change | SDK frozen; XML-doc `whoami` mentions cosmetic. |
| `tests/AAuth.Conformance` `Scope="whoami"` literals | Arbitrary SDK test values, not sample-coupled. |
| `aauth-spec/**` | Upstream spec drafts; not ours to rename. |
| New `wallet.charge` UI step in GuidedTour/SampleApp | Exercised via AgentConsole + Keycloak tests only (mirrors today's `/jwt/admin`); no mandatory new UI flow. |

---

# Narrative-coherence follow-up (Phases 11–16, 2026-06-09)

After the split, a clarity pass added per-flow "What Aria is trying to do"
narratives and surfaced two off-theme inconsistencies (see research.md
**Follow-up — narrative coherence pass**). These phases make the whole demo
surface read as one coherent Aria travel story. **Same guiding rules apply**
(preservation guarantee, no back-compat aliases, SDK frozen, build 0/0 after
each phase).

## Phase 11 — Aria narratives + collapsible UX + chevron fix

Add a plain-language "What Aria is trying to do" callout to every SampleApp flow
page and every GuidedTour flow, gloss the first **Aria** mention with "(your AI
travel assistant)", clarify the Bootstrap flow's enrol-vs-self-issue audience,
and make every narrative collapsible so it does not eat screen space.

### Files

| File | Change |
|---|---|
| `samples/SampleApp/Components/Pages/{Hwk,JwksUri,JktJwt,Jwt,Deferred,Federated,Mission,CallChain,MissionCallChain}.razor` | Narrative `<details class="alert alert-primary aria-narrative" open>` with `<summary>📖 What Aria is trying to do</summary>`; first Aria glossed. |
| `samples/SampleApp/wwwroot/app.css` | `details.aria-narrative > summary` styling; `list-style-position: inside` so the disclosure chevron stays inside the padded `.alert` box (overflow fix). |
| `samples/GuidedTour/Components/Pages/Tour.razor` | `flow-picker__desc` becomes `<details open>` with summary; per-flow "What Aria is trying to do" lead sentence; Bootstrap flow gains the "who enrols vs hosted self-issues" note. |
| `samples/GuidedTour/wwwroot/app.css` | `flow-picker__desc > summary` styling. |
| `samples/GuidedTour/playwright-tests/picker.spec.ts` | Locator `p.flow-picker__desc` → `details.flow-picker__desc`. |

### Definition of Done

- [x] Every SampleApp flow page + GuidedTour flow has a collapsible narrative.
- [x] Disclosure chevron stays inside the SampleApp alert box (no overflow).
- [x] GuidedTour `picker` e2e passes against the new `details` selector.
- [x] `dotnet build` 0/0 for SampleApp + GuidedTour.

---

## Phase 12 — Orchestrator → Concierge rename

Rename the intermediate call-chain service to **Concierge** to fit the Aria
travel narrative (research.md Finding A). Full rename: folder, project, scope,
identity, config keys, actor enum, Makefile, UI, tests. **Keep port `:5200`.**

### Implementation decisions

- **Name:** `Concierge` (a travel concierge arranges things with other providers
  on the user's behalf — exactly the Agent → intermediate → downstream pattern).
- **Scope:** `orchestrate` → `concierge`. Demo-defined, not an SDK constant.
- **Identity:** `aauth:orchestrator@localhost:5200` → `aauth:concierge@localhost:5200`.
- **Port:** unchanged (`:5200`) — infra, no narrative value in churn.
- **Folder/project:** `samples/Orchestrator/` → `samples/Concierge/`,
  `Orchestrator.csproj` → `Concierge.csproj` (use `git mv` to preserve history).
- **Config keys:** `OrchestratorUrl` → `ConciergeUrl`, `AAuth:Orchestrator` →
  `AAuth:Concierge`. The Concierge's own downstream keys (`AAuth:Downstream`,
  `AAuth:MissionDownstream`) keep their generic names (they describe *what they
  point at*, not the service).
- **Actor enum:** `Actor.Orchestrator` → `Actor.Concierge` (GuidedTour swimlane).

### Files

| File | Change |
|---|---|
| `samples/Orchestrator/**` → `samples/Concierge/**` | `git mv` folder + `.csproj`; rename namespace/marker if any; scope const `concierge`; default identity `aauth:concierge@…`; comments reframed (concierge arranges downstream calls). |
| `AAuth.slnx` | Project path + name. |
| `samples/Concierge/appsettings.json` | `AAuth:AgentId` identity; keep `:5200`. |
| `samples/SampleApp/appsettings.json` + `Components/Pages/{CallChain,MissionCallChain}.razor` + `Home.razor` | `AAuth:Orchestrator`→`AAuth:Concierge`; UI labels "Orchestrator"→"Concierge"; scope `orchestrate`→`concierge`; local `orchestratorUrl`→`conciergeUrl`. |
| `samples/GuidedTour/{TourOptions,TourSession,CodeSnippets}.cs` + `Components/Pages/Tour.razor` + `EntityHighlighter.cs` | `OrchestratorUrl`→`ConciergeUrl`; `Actor.Orchestrator`→`Actor.Concierge`; swimlane label; scope payload `concierge`; narrative prose; comments. |
| `samples/GuidedTour/appsettings.json` | `OrchestratorUrl`→`ConciergeUrl`. |
| `Makefile` | `ORCH_PROJECT`/`ORCH_URL`→`CONCIERGE_*`; target `orchestrator`→`concierge`; help text + port comment. |
| `tests/e2e/playwright.config.ts` + `helpers/{agents,consent,tour}.ts` | project boot path; `orchestrator` URL key→`concierge`; identity assertions; comments. |
| `samples/{SampleApp,GuidedTour}/playwright-tests/*call-chain*.spec.ts` + `mission-call-chain.spec.ts` | identity assertions `aauth:concierge@…`; scope `concierge`; comments. |
| `docs/workflows/call-chaining.md`, `docs/advanced/interaction-chaining.md`, `docs/reference/{configuration,dependency-injection}.md`, `docs/getting-started.md` | scope/identity/name; narrative; config tables. (Deeper doc prose handled in Phase 15.) |

> **Note:** `src/AAuth` XML-doc mentions of "orchestrator" (2) are generic
> ("a resource acting as an agent, e.g. an orchestrator") and stay — the SDK is
> theme-agnostic and frozen.

### Definition of Done

- [x] Folder/project/solution renamed; build 0/0; `make concierge` runs `:5200`.
- [x] Scope `concierge` + identity `aauth:concierge@…` everywhere in samples/tests.
- [x] No `Orchestrator`/`orchestrate` left in samples, config, Makefile, or e2e
      (except the 2 generic SDK doc-comments and historical plan/log entries).
- [x] Call-chain + mission-call-chain e2e pass (both apps). _(call-chain.spec: 5 passed both apps)_

---

## Phase 13 — Mission travel-theme + stale scope-description cleanup

Re-theme the Mission demo from inbox → trip planning (research.md Finding B),
preserving all gate semantics; fix stale `whoami`-era scope descriptions.

### Implementation decisions

- **Mission description:** "Plan my weekend trip to Seattle." (planning intent
  only, so `trips.book` stays legitimately out-of-scope).
- **Pre-approved tools:** `compare_options` ("Compare flight and hotel
  options"), `add_to_calendar` ("Add an itinerary item to the calendar").
- **Non-approved (prompting) tool:** `cancel_booking` ("Cancel an existing
  booking") — destructive, parallels old `delete_inbox`.
- **Scopes unchanged:** `trips.read` (silent, in-scope), `trips.book` (prompts).
- **Clarification strings** (MissionCallChain + conformance seam tests) re-themed
  to trips (e.g. "Needed to compare available trip options.").

### Files

| File | Change |
|---|---|
| `samples/SampleApp/Components/Pages/Mission.razor` | Mission description; tools `compare_options`/`add_to_calendar`/`cancel_booking`; gate commentary + step labels; fix stale scope descriptions (`trips.read`/`trips.book`). |
| `samples/SampleApp/Components/Pages/MissionCallChain.razor` | Clarification question/answer + any inbox references → trips. |
| `samples/MissionAgent/Program.cs` + `README.md` | CLI mission proposal strings, tool names, console output labels, mermaid/narrative. |
| `samples/GuidedTour/TourSession.cs` + `CodeSnippets.cs` + `Components/Pages/Tour.razor` | Mission step titles/narratives, proposal payload tools, gate summary lines, UI prose (`send_email`/`delete_inbox`→new tools). |
| `tests/AAuth.Conformance/Missions/{MissionHeaderSeamTests,ChallengeClarificationSeamTests}.cs` | Re-theme demo strings (`"Keep the inbox under control"`, `"Needed to summarize the inbox."`) — self-contained, not protocol. |
| `tests/e2e/helpers/tour.ts` | Step comment `delete_inbox`→`cancel_booking`. |
| `tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs` | `send_email` demo tool string in row09–11 missions → `add_to_calendar` (keep behavior). |

### Definition of Done

- [x] Mission demo reads as one travel story; no `inbox`/`email`/`send_email`/
      `delete_inbox`/`summarize` strings remain in samples (grep clean).
- [x] All five gates still demonstrated (silent in-scope, prompt out-of-scope,
      silent pre-approved tool, prompt non-approved tool, mission creation).
- [x] Stale `whoami`-era scope descriptions corrected.
- [x] Unit + conformance + Mission e2e (both apps) green. _(133 mission/governance conformance + 12 MissionAgent integration green; mission e2e validated in Phase 16 run)_

---

## Phase 14 — Console / CLI code + comment sweep

Explicitly verify the console apps and CLIs (not just the Blazor UIs) carry
correct code, identities, scopes, and **comments** after Phases 12–13.

### Files

| File | Change |
|---|---|
| `samples/Concierge/Program.cs` (ex-Orchestrator) | Header/banner comments reframed to the concierge role; scope/identity correct; any console `Console.WriteLine` labels. |
| `samples/MissionAgent/Program.cs` | Section banners, gate comments, console output labels all travel-themed and scope-accurate (`trips.read`/`trips.book`, new tools). |
| `samples/AgentConsole/Program.cs` + `README.md` | Mode→path table (`/pseudonymous`,`/identified`,`/anchored`,`/events`), scope mentions, comments; confirm no `whoami`/`orchestrate` leftovers. |
| `samples/LiveWhoAmITest/Program.cs` | **Review only** — confirm it is intentionally external (`whoami.aauth.dev`); add a one-line comment clarifying it is deliberately *not* migrated, if missing. |

### Definition of Done

- [x] Each console/CLI builds and runs (`AgentConsole` all modes; `MissionAgent
      --auto` full lifecycle; `Concierge` serves `:5200`).
- [x] Comments/banners describe the *current* Aria roles, not legacy ones.
- [x] `LiveWhoAmITest` clearly marked as the intentional external exception.

---

## Phase 15 — Docs & READMEs refresh (Concierge + mission theme)

Redo the documentation pass focused on the Phase 12–14 changes (the original
Phase 6 predates them).

### Files

| File | Change |
|---|---|
| `samples/Concierge/README.md` (renamed) | Re-title; concierge role; scope `concierge`; identity; curl examples. |
| `samples/README.md` | Service table row + overview prose: Orchestrator→Concierge. |
| `samples/MissionAgent/README.md` | Mission narrative + tools (covered in Phase 13; re-verify here). |
| `docs/workflows/call-chaining.md`, `docs/advanced/interaction-chaining.md` | Concierge name/scope/identity; diagrams; narrative; mission-theme examples. |
| `docs/reference/configuration.md`, `docs/reference/dependency-injection.md` | `ConciergeUrl`/`AAuth:Concierge` config tables. |
| `docs/getting-started.md`, `docs/concepts.md` | Generic "orchestrator" prose vs the named Concierge sample; mission tools-vs-scopes example re-themed. |
| `tests/e2e/README.md` | Service table label. |

### Definition of Done

- [x] No stale `Orchestrator`/`orchestrate`/inbox-mission references in `docs/`
      or sample READMEs (grep clean, excluding historical plan/log).
- [x] Config tables list `ConciergeUrl` / `AAuth:Concierge`.
- [x] Markdown lints/links resolve. _(also re-themed standalone mission examples in mission-governed-access, mission-governance-clients, clarification-chat, error-handling to the trip story for cross-doc coherence)_

---

## Phase 16 — Focused new-reader clarity / consistency / spec-accuracy review

Re-run the Phase 10 three-lens review, scoped to the Phase 11–15 surface.

### Approach

- Reviewer subagent over the changed files with the same three lenses
  (new-reader comprehension, cross-file consistency, spec accuracy), plus a
  fourth **theme-coherence** lens: does every flow now read as one Aria travel
  story (Concierge arranges; the mission plans a trip), with no inbox/email or
  Orchestrator residue and no scope/description drift?
- Severity-grade; remediate blockers + majors in owning files; log minors.

### Definition of Done

- [x] Review run; findings severity-graded with file:line (+ cited spec ref for
      accuracy findings). _(0 blocker, 5 major — all doc-only stale `concierge@ap.example` identities; 0 minor)_
- [x] All blocker + major findings remediated; minors logged. _(5 majors fixed → `concierge@concierge.example`, consistent with self-hosted identity + the doc's `https://concierge.example`)_
- [x] A new reader can trace the full Aria narrative — Profile → Calendar →
      Trips → Wallet, Concierge delegation, and the trip-planning mission —
      without contradiction. _(verified by review lens D + MissionAgent --auto live run)_
- [x] `dotnet build AAuth.slnx` 0/0; unit + conformance + e2e green. _(387 unit + 481 conformance + 36 e2e passed, 1 skipped)_

---

## Phase 17 — ASCII flow diagrams → mermaid sequence diagrams

Convert the remaining hand-drawn ASCII flow diagrams in our docs/READMEs to
mermaid `sequenceDiagram` blocks (the other workflow docs already used mermaid).
Doc-only; no code or build impact.

### Files

| File | Change |
|---|---|
| `samples/Concierge/README.md` | Call-chain flow (Agent → Concierge → PS → Calendar): 401 challenge, `upstream_token` exchange, nested `act`, combined 200. |
| `docs/advanced/interaction-chaining.md` | Interaction-chaining flow: chained 202, browser consent, poll loop, final 200. |
| `docs/workflows/call-chaining.md` | One-line scenario topology expanded to a sequence diagram of the 7-step delegation; numbered walkthrough kept alongside. |

### Out of scope (intentionally NOT converted)

- Workflow docs already on mermaid (`ps-asserted-access`, `deferred-consent`,
  `federated-access`, `resource-managed-access`, `mission-governed-access`).
- Non-flow ASCII: the key-store directory tree (`key-management.md`), the
  annotated HTTP-header example (`signing-modes/overview.md`), markdown tables.
- `aauth-spec/**` ASCII diagrams (upstream drafts).

### Definition of Done

- [x] All three hand-drawn flow diagrams in our docs/READMEs are mermaid
      sequence diagrams; each accurately reflects the protocol exchange.
- [x] No plain-fence ASCII *flow* diagrams remain in `docs/` or sample READMEs
      (verified by grep for box-drawing/arrow art; only non-flow ASCII remains).
- [x] Diagram actors/messages match the live behavior (Concierge identity,
      ports, token types) validated in Phases 12–16.

---

## Phase 18 — GuidedTour Overview (home) page

Add a landing page at `/` that introduces Aria + the overall narrative + the
role of the Guided Tour, and indexes every flow as a card that deep-links into
the live walkthrough. The tour itself moves to `/tour`.

### Files

| File | Change |
|---|---|
| `samples/GuidedTour/Components/Pages/Home.razor` | **New** static landing page: "Meet Aria" intro, four-server legend (Profile/Calendar/Trips/Wallet), the tour's role, and an 8-card flow index linking to `/tour?flow=<Mode>`. |
| `samples/GuidedTour/Components/Pages/Tour.razor` | `@page "/"` → `@page "/tour"`; add `[SupplyParameterFromQuery] Flow` read in `OnInitializedAsync` to preselect a deep-linked flow; add `← Overview` link in the topbar. |
| `samples/GuidedTour/wwwroot/app.css` | `.home`, `.intro`, `.flow-index`, `.flow-card*`, `.srv*`, `.topbar__back`/`__tag` styles. |
| `samples/GuidedTour/README.md` | Document the Overview page + `/tour?flow=` deep-links. |
| `tests/e2e/helpers/tour.ts` | `openTour` navigates to `/tour`. |
| `samples/GuidedTour/playwright-tests/smoke.spec.ts` | Smoke loads `/tour`. |
| `samples/GuidedTour/playwright-tests/home.spec.ts` | **New** specs: overview introduces Aria + indexes all 8 flows; a card deep-links into the matching flow (asserts `#flow-select` value) and `← Overview` returns home. |

### Definition of Done

- [x] `/` shows the Aria intro + the role of the tour + an 8-flow index; `/tour`
      runs the walkthrough; `/tour?flow=<Mode>` preselects that flow.
- [x] `home.spec.ts` passes (overview content + deep-link); `smoke` + all
      existing guided-tour specs pass against the `/tour` route.
- [x] `dotnet build` 0/0 for GuidedTour; home page verified in-browser.

