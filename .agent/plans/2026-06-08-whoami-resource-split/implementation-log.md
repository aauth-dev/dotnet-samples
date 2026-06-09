# Implementation Log — Decisions, Deviations & Open Questions

> Living log for the AArai resource-server refactor. Maintained by the
> implementing agent while the owner is AFK. The owner reviews **all** entries
> here in one pass at the end of implementation. See
> [implementation-plan.md](implementation-plan.md) and [research.md](research.md)
> for the agreed design.

## How to read this

- **Decisions taken** — choices I made to keep moving, with rationale. Revert if
  you disagree.
- **Deviations from plan** — where reality differed from the plan/research.
- **Open questions / inputs needed** — things I want your ruling on. Where I had
  to proceed, I picked a default (marked) and noted it so you can override.
- **Subagent decision requests** — when the plan says "deploy a subagent to get
  a decision," the prompt + the subagent's recommendation are logged here.

Each entry: `[YYYY-MM-DD] [Phase N] <title>` with status
`PROCEEDED (default X)` / `BLOCKED` / `RESOLVED`.

---

## Decisions taken

### [2026-06-08] [Setup] Branch base
- **Decision:** Created branch `refactor/aria-resource-servers` off the current
  checkout `feat/missions-ps-governance` (not `main`), because the working tree
  already carried the uncommitted SDK `DefaultScope` change and the plan docs
  from this session.
- **Carried-over uncommitted changes:** `src/AAuth/Access/AAuthAccessServerEndpoints.cs`,
  `src/AAuth/Person/AAuthPersonServerEndpoints.cs` (DefaultScope → empty), plus
  the new `.agent/plans/2026-06-08-whoami-resource-split/` docs.
- **Input needed?** Confirm this is the right base branch, or tell me to rebase
  onto `main` before you merge.

---

## Deviations from plan

### [2026-06-08] [Phase 1] slnx auto-populated MockResourceServers folder
- Creating the four `.csproj` files caused the IDE to auto-add them to
  `AAuth.slnx` (incl. a `MockResourceServers` solution folder). I only had to
  remove the `WhoAmI` line manually. No action needed — matches plan intent.

### [2026-06-08] [Phase 1] Full-flow DoD items deferred to Phase 7
- Phase 1 DoD includes "Profile `/identified` enforces `AAuth.Identified`" and
  "Calendar `/events/admin` 403 for non-owner". These require a signed
  agent-token + PS exchange, which is exercised by the rewritten integration
  tests in Phase 7. Server-level DoD (build, boot, well-known, JWKS, index JSON)
  is verified now; the auth-gated assertions are validated in Phase 7.
  Smoke-tested: all four servers boot on :5000–:5003 and serve `/` +
  `/.well-known/aauth-resource.json` + `/.well-known/jwks.json` correctly.

---

### [2026-06-08] [Phase 3] Orchestrator now has TWO downstreams (deviates from research flow-8 table) — NEEDS REVIEW
- **What changed:** The Orchestrator previously pointed a single `Downstream`
  (`:5000` WhoAmI) at both the plain chain (`/jwt`) and the mission chain
  (`/jwt/mission`). The Aria split puts those on different hosts, so the
  Orchestrator now has two configs:
  - `AAuth:Downstream` = `:5001` Calendar, plain chain hits `/events`
    (`calendar.read`).
  - `AAuth:MissionDownstream` = `:5002` Trips, mission chain hits `/trips`
    (`trips.read`, mission-aware).
- **Why I deviated:** The research "flow 8 (Mission + Call Chain)" mapping table
  said the mission chain's hop-2 goes to **Calendar `/events`**. But Calendar is
  a plain three-party server (NOT mission-aware), so routing the mission chain
  there would silently drop the mission-aware behaviour that flow 8 exists to
  demonstrate. The faithful preservation of behaviour requires the mission chain
  to hop to a **mission-aware** resource → **Trips `/trips`**. I implemented the
  faithful version.
- **Impact:** `PendingStore.Entry` gained a `DownstreamBase` field;
  `RunChainAsync` takes a downstream base URL. GuidedTour/SampleApp call-chain
  (flow 5, plain) still → Calendar `/events`. Mission-call-chain (flow 8) →
  Trips `/trips`.
- **Input needed:** Confirm this is acceptable (mission chain → Trips, not
  Calendar). If you really want the mission chain to hop to Calendar, the flow
  loses its mission-aware demonstration and I'd need to make Calendar
  mission-aware too. Recommendation: keep Trips.
- The research flow-8 table row should be corrected to read "chain → **Trips**
  `/trips` (`trips.read`)" — I will fix it in Phase 6 docs unless you object.

## Open questions / inputs needed

### [2026-06-08] [Phase 3] Mission call-chain downstream target — see deviation above
- Resolved by me as **Trips `/trips`** (mission-aware) to preserve behaviour;
  flagged for your confirmation.

### [2026-06-08] [Phase 4] GuidedTour actor/swimlane/URL-highlight model — design decision (NEEDS REVIEW)
- **Finding (thorough subagent sweep):** GuidedTour bakes single-resource
  assumptions into its visual model: a single `Actor.Resource` enum
  (StepRecord.cs#L88-L95), one "Resource:" URL in the top actor bar bound to
  `WhoAmIUrl` (Tour.razor#L12), one `hl-resource` highlight origin
  (EntityHighlighter.cs#L27), and static per-flow swimlanes using `Actor.Resource`
  (Tour.razor#L234-L260). `EffectiveResourceUrl`, `MissionResourceUrl`,
  `MissionElevatedResourceUrl`, consent-setup scopes, and several narratives
  hardcode WhoAmI/`whoami`.
- **Decision (mine, low-churn + faithful):** Keep the single `Actor.Resource`
  enum — every Aria flow still talks to exactly ONE resource server, so one
  resource lane per flow is correct. Make the resource's **display name + URL
  flow-dependent** via a `TourMode → (name, url)` map: Identity→Profile :5000,
  Autonomous/Deferred/CallChain→Calendar :5001, Mission/MissionCallChain→Trips
  :5002, Federated→Wallet :5003. Top bar shows the active flow's resource;
  EntityHighlighter recognises all four origins as `hl-resource`; swimlane
  resource lane labelled with the flow's server name.
- **Rejected alternative:** Four distinct resource enum actors — high churn, and
  no single flow ever shows two resource servers at once.
- **Plan impact:** Phase 4 expanded with the full UI inventory + this decision;
  added a dedicated **Phase 8 — GuidedTour visual / actor-model verification
  (browser walkthrough)**; old Phases 8/9 renumbered to 9/10.
- **Input needed:** Confirm single-`Actor.Resource` + flow-dependent label/URL is
  acceptable.

---

## Subagent decision requests

_(none yet)_

---

## Validation runs

_(test/e2e/CLI run results recorded here as phases complete)_

### [2026-06-08] SDK suites (after DefaultScope change)
- `dotnet build AAuth.slnx` 0/0.
- `dotnet test tests/AAuth.Tests` → 387 passed.
- `dotnet test tests/AAuth.Conformance` → 481 passed.

### [2026-06-08] Phase 1–3 runtime smoke (manual, AgentConsole + AP + PS + servers)
- All four servers boot on :5000–:5003; `/`, `/.well-known/aauth-resource.json`,
  `/.well-known/jwks.json` correct.
- Profile identity `hwk → /pseudonymous` → 200 (`mode:pseudonymous`).
- Calendar three-party `/events` (demo) → 200 `scope:["calendar.read"]`.
- Calendar RBAC `/events/admin`: demo → 200 `roles:["calendar.owner"]`; guest → 403.
- Calendar step-up `/events/write` (demo) → 200 `scope:["calendar.write"]`.
- NOTE: ran PS in autonomous mode (no RequireConsent). Deferred/consent +
  mission + federated + call-chain runtime paths validated later (Phase 7/8).
- Cache hygiene: AgentConsole enrollment cache lives at
  `~/.local/share/aauth-agent-console/<sub>.json` and the key store at
  `~/.aauth/keys`. Clear both between runs that change keys (recorded for reuse).

### [2026-06-08] Phase 4 GuidedTour — compile + static verification
- All 12 sample projects build 0/0 (Profile/Calendar/Trips/Wallet, MockPS/AS/AP,
  Orchestrator, AgentConsole, MissionAgent, GuidedTour, SampleApp).
- GuidedTour migrated: appsettings (4 resource URLs), TourOptions (4 URL props +
  `call-chain targets Calendar`), TourSession (`ResourceBaseUrl`/
  `ResourceDisplayName` flow→resource map; EffectiveResourceUrl → Profile paths;
  MissionResourceUrl/Elevated → Trips; FederatedTargetUrl → Wallet; metadata
  fetch + consent scopes/resources; all narrative text), EntityHighlighter (all
  four origins → `hl-resource`), Tour.razor (top bar shows active flow's
  resource name+URL; swimlane labels Profile/Calendar/Trips/Wallet; added
  `ThreePartyLanes` for autonomous/deferred), CodeSnippets, all 10 playwright
  specs (scope/path/text assertions).
- Also fixed an Orchestrator gap found via the call-chain spec: the `chain`
  response field was hardcoded `Agent → Orchestrator → WhoAmI`; now derives
  `Calendar` (plain) / `Trips` (mission) from the downstream path.
- Repo grep: zero `whoami|WhoAmI|/jwt|/hwk|/jwks-uri|/jkt-jwt|/federated` in
  GuidedTour code (README is Phase 6).
- Browser-visual verification (actor bar, highlighting, swimlanes rendered) is
  the dedicated Phase 8 walkthrough — not yet run.

### [2026-06-08] Phase 5 SampleApp — done (via coding subagent + my verification)
- appsettings `Resource :5000` → `Profile/Calendar/Trips/Wallet` (:5000–:5003).
- 10 pages re-targeted: Hwk→Profile `/pseudonymous`, JwksUri→Profile `/identified`,
  JktJwt→Profile `/anchored`, Jwt+Deferred→Calendar `/events` (`calendar.read`),
  Federated→Wallet `/wallet` (`wallet.read`), CallChain hop-2→Calendar `/events`,
  Mission→Trips `/trips`+`/trips/book` (`trips.read`/`trips.book`),
  MissionCallChain elevated→Trips `/trips/book` + chain→Trips, Home prose.
  Displayed code snippets + prose updated too.
- All 11 playwright specs updated (scope/path/text). SampleApp `@page` routes
  (`/hwk`, `/jwt`, …) KEPT per plan decision (low churn; flagged below).
- Build 0/0; grep clean except the intentional `@page`/`goto` route lines.

### [2026-06-08] [Phase 5] SampleApp page routes kept as-is — NEEDS REVIEW
- The SampleApp's own nav routes stay `/hwk`, `/jwt`, `/federated`, `/mission`,
  etc. even though the page at `/jwt` now calls Calendar `/events`. This is the
  plan's recorded default (minimize churn). If you prefer narrative-consistent
  routes (`/profile`, `/calendar`, `/trips`, `/wallet`), say so and I'll rename
  routes + nav links + `goto()` calls. Recommendation: optional polish, not
  required for correctness.

### [2026-06-08] Phase 7 (Makefile + e2e harness + integration tests) — done
- Makefile: WHOAMI_* vars → PROFILE/CALENDAR/TRIPS/WALLET projects + URLs; new
  `resources` target boots all four; `agent` defaults to Profile; demo/
  demo-keycloak/demo-mission boot the right servers; Keycloak ResourceName →
  wallet; agent-federated → Wallet `/wallet`; role text whoami-admin →
  wallet.payer; mission text → trips.read/trips.book. Only LiveWhoAmITest refs
  remain (intentional).
- e2e harness: playwright.config webServer boots the four servers; helpers/
  agents.ts `Urls.whoami` → `profile/calendar/trips/wallet`; consent.ts +
  tour.ts comments updated.
- Integration tests (via coding subagent + my verification):
  - WhoAmIFlowTests.cs → **CalendarFlowTests.cs** (git mv), hosts
    `Calendar.Entry`, paths/scopes/role → Calendar taxonomy.
  - MockAccessServerTests / KeycloakTests → wallet.read/wallet.charge/
    wallet.payer (matches the changed stub policy). Subagent also fixed a stub
    bug in KeycloakTests (`Contains(":")` → `Contains("wallet.charge")`).
  - MockPersonServerTests → calendar.*; FederationTests → wallet.read;
    MissionAgentFlowTests → trips.read/trips.book.
  - **AAuth.Tests.csproj** project reference WhoAmI.csproj → Calendar.csproj
    (necessary; the deleted WhoAmI project broke the build). Flagged: this is
    outside Integration/ but unavoidable.
- VALIDATION: full solution builds 0/0; 387 unit + 481 conformance pass; grep
  clean in tests/AAuth.Tests/Integration (no whoami/WhoAmI/jwt).
- Still pending: live e2e (playwright) run + CLI permutation runs (the big
  validation), and Phase 6 docs, Phase 8 GuidedTour browser walkthrough,
  Phase 9/10 audits.

### [2026-06-08] Response field rename: `mode` → `signingMode` / `accessMode` (spec alignment)
- Per docs/concepts.md, the demo response `mode` field conflated two distinct
  spec taxonomies. Renamed so each payload self-describes its concept:
  - **Profile** endpoints (signing-mode demo): `signingMode` + `scheme`
    (`pseudonymous`/`agent-identity`).
  - **Calendar/Trips/Wallet** (access-mode demos): `accessMode` + `scheme`
    (`three-party`/`four-party`/`identity-based` on the index).
- Also fixed: `jkt-jwt` `mode` was briefly `"anchored"`; reverted to spec-correct
  `pseudonymous` (concepts.md maps jkt-jwt → Pseudonymous identity type). The
  `/anchored` PATH name stays (describes the key mechanism); the `signingMode`
  VALUE reports the spec identity type. Code comment added.
- These response bodies are NOT spec-defined (spec governs headers/tokens), so
  the rename is safe. Updated all GuidedTour + SampleApp playwright specs and the
  displayed code snippets in the razor pages.

### [2026-06-08] LIVE E2E VALIDATION — PASSED
- `npx playwright test` (both projects, boots all 11 services):
  **32 passed, 1 skipped, 0 failed** (~2.2 min).
- Earlier iteration caught 3 real assertion mismatches (jkt-jwt mode, mission
  `access` discriminator), all resolved by preserving spec-correct values
  (`pseudonymous`, `mission-elevated`).
- Full solution builds 0/0; 387 unit + 481 conformance still green.

### [2026-06-08] Phase 6 (Docs + READMEs) — done
- Mechanical doc sweep (via coding subagent + my verification) across 20 files:
  all of `docs/**` + top-level `README.md`/`docs/README.md` + 7 sample READMEs
  (AgentConsole, GuidedTour, MissionAgent, MockAccessServer, MockAgentProvider,
  MockPersonServer, Orchestrator) + `samples/README.md`. `DefaultScope` doc rows
  updated to empty default.
- Created 5 NEW READMEs: `samples/MockResourceServers/README.md` (suite index +
  narrative + signing-mode↔path table + response-field convention) and one per
  server (Profile/Calendar/Trips/Wallet).
- `samples/README.md` header now says "Thirteen sample applications" with the
  four Aria servers linked under `MockResourceServers/`.
- Verified: no dangling links to the deleted `samples/WhoAmI/`; remaining
  whoami/route grep matches are all allowed (SampleApp `:5240` UI routes,
  signing-mode scheme names `hwk`/`jwks_uri`, external `explorer.aauth.dev` /
  `whoami.aauth.dev` links, LiveWhoAmITest). Markdown lints clean (0 errors).

### [2026-06-08] Phase 8 (GuidedTour visual / actor-model browser verification) — done
- NOTE: the integrated browser tool runs on the host and can't reach the
  container's `localhost:5400`. Did the visual verification via a temporary
  Playwright spec (inside the container) that asserts the top actor bar + URL,
  then screenshots the bar + swimlanes. Spec removed after capture.
- Booted the full demo stack (4 resource servers + PS/AP/AS/Orchestrator +
  GuidedTour) and verified per flow:
  - Actor bar: Identity→**Profile** :5000, Autonomous→**Calendar** :5001,
    Mission→**Trips** :5002, Federated→**Wallet** :5003 (4/4 assertions passed).
  - Screenshots confirm: green-highlighted server URL in the bar, the swimlane
    resource lane labelled with the server name ("Trips", "Wallet", …), and
    narratives using the Aria taxonomy (`/wallet`, `trips.read`, `trips.book`,
    four-party AS federation text). Zero `whoami`/`/jwt` visible.
- No visual defects; the only UI fixes were the earlier spec-alignment of the
  `signingMode`/`mode` response values, already resolved.

### [2026-06-08] Phase 9 (per-artifact coverage audit) — done
- Ran a repo-wide categorized grep (instead of per-file subagents — same
  coverage). Findings by category:
  - **(a) missed, FIXED:** `samples/MockAccessServer/Policy/KeycloakOptions.cs`
    `ResourceName` C# default `"whoami"` → `"wallet"` (appsettings was already
    `wallet`, but the code fallback was stale); stale "WhoAmI sample" comment in
    `samples/MockPersonServer/Program.cs` marker-type note. Both rebuilt 0/0.
  - **(b) exempt:** `src/AAuth` SDK XML-doc (2) — frozen per user; one
    (`AAuthUrl.cs`) is now factually stale ("the WhoAmI and AgentConsole
    samples") — see open question below. `tests/AAuth.Tests` (26) +
    `tests/AAuth.Conformance` (33) use `whoami`/`whoami:admin` as ARBITRARY
    placeholder scope values for SDK-primitive unit/conformance tests (not
    sample-coupled — same rationale the plan recorded for conformance). External
    `whoami.aauth.dev` references.
  - **(c) intentional:** `.copilot-tracking/pr/**` (27) historical PR review
    docs (frozen like `.agent/plans`); the "replace the former single WhoAmI"
    sentence I wrote in `MockResourceServers/README.md` explaining the migration.
- samples/ + docs/ are now grep-clean of non-route, non-external legacy refs.

## Open questions / inputs needed (continued)

### [2026-06-08] [Phase 9] Stale SDK XML-doc comment (src/AAuth/AAuthUrl.cs)
- `AAuthUrl.cs:12` says "the WhoAmI and AgentConsole samples can run" — WhoAmI is
  deleted. Per your "SDK frozen except DefaultScope" instruction I left it
  untouched. It's a cosmetic doc comment (no behavior). **Input:** OK to leave,
  or want a one-line comment fix ("the resource-server and AgentConsole
  samples")? Same applies to the `AAuth.Role.whoami-admin` example in
  `AAuthResourceServiceCollectionExtensions.cs:179`.

### [2026-06-08] Phase 10 (clarity / consistency / spec-accuracy review) — done
- Review subagent over the full migrated doc set with three lenses (new-reader
  comprehension, cross-file consistency, spec accuracy). **Verdict: coherent and
  spec-accurate; ZERO blocker/major; 1 minor.**
- Minor (FIXED): `tests/e2e/README.md` still listed "WhoAmI (resource) 5000" and
  "Agent → Orchestrator → WhoAmI". Updated the service table to all four Aria
  servers (+ MockAccessServer) and the call-chain note → Calendar.
- Confirmed: jkt-jwt correctly documented as **pseudonymous** (not agent
  identity); scope correctly described as **optional**; four-party `aud`=AS
  behavior correct; signing-mode scheme names unchanged; Orchestrator plain
  chain → Calendar, mission chain → Trips consistently everywhere.

### [2026-06-08] FULL VALIDATION — all green
- Build: `dotnet build AAuth.slnx` 0 warnings / 0 errors.
- Unit: 387 passed. Conformance: 481 passed.
- e2e (Playwright, both projects, 11 services booted): 32 passed, 1 skipped.
- CLI permutations (manual, fresh stack):
  - AgentConsole identity → Profile: `hwk`→200 `signingMode=pseudonymous`,
    `jwks_uri`→200 `agent-identity`, `jkt-jwt`→200 `pseudonymous`.
  - AgentConsole three-party → Calendar: `/events`, `/events/write`,
    `/events/admin` all 200 (`accessMode=three-party`); guest `/events/admin`→403
    (RBAC deny).
  - MissionAgent `--auto` → Trips: full 10-step lifecycle — `trips.read` silent
    (gate 2a), `trips.book` out-of-mission prompt→grant (gate 3), tool
    permissions, mission terminated. `access=mission` / `access=mission-elevated`
    preserved.
- Remaining optional / your-call items (see Open questions): SampleApp page-route
  rename, Orchestrator mission-chain→Trips confirmation, branch base, SDK XML-doc
  cosmetic comments, Keycloak Docker run (`make demo-keycloak`) not executed here.

## Owner review resolutions (2026-06-09)

The owner reviewed the open questions and answered 1–5:

1. **Rebase onto main — DONE.** Fetched `origin/main`, confirmed
   `feat/missions-ps-governance` is fully merged (origin/main differs only by the
   PR-#32 merge commit; 0 files differ in tree). Stash → `git rebase origin/main`
   (conflict-free) → stash pop. Branch now based on `271c537` (origin/main HEAD,
   tag v0.1.0-alpha.12). All changes intact; build 0/0.
2. **Orchestrator mission-chain → Trips — CONFIRMED & explained.** Calendar is a
   plain three-party server (not mission-aware) and would silently drop the
   forwarded mission, defeating the flow-8 demonstration. Trips is mission-aware,
   so the mission round-trips. Research flow-8 / mission-call-chain table rows
   corrected (`→ Calendar` → `→ Trips`).
3. **SampleApp page-route rename — DONE.** Routes now narrative-consistent:
   `/hwk`→`/pseudonymous`, `/jwks-uri`→`/identified`, `/jkt-jwt`→`/anchored`,
   `/jwt`→`/calendar`, `/deferred`→`/calendar-deferred`, `/federated`→`/wallet`,
   `/mission`→`/trips`; `/call-chain` + `/mission-call-chain` kept (multi-hop).
   Updated `@page` directives, NavMenu links, Home cards, the Federated→Deferred
   cross-link, all playwright `goto()`s, and `home.spec.ts` href assertions.
   SampleApp e2e: 14 passed + home spec re-run 2 passed (was the 1 failure).
4. **SDK XML-doc cosmetic comments — FIXED.** `AAuthUrl.cs` "the WhoAmI and
   AgentConsole samples" → "the resource-server and AgentConsole samples";
   `AAuthResourceServiceCollectionExtensions.cs` `AAuth.Role.whoami-admin`
   example → `AAuth.Role.calendar.owner`. (Only these two; build 0/0.)
5. **Keycloak Docker run — owner will test.** `make demo-keycloak` left for the
   owner to run (realm JSON validated well-formed; stub-policy equivalent tested).

## Follow-up fix (2026-06-09): SampleApp snippet authz enforcement

Owner observed that some SampleApp displayed code snippets *return* the scope
(`scope = r.Scopes // ["calendar.read"]`) but don't *enforce* it. Audited all
page snippets vs. the real resource servers. Findings + fixes:

- **GAP — Jwt.razor (`/events`):** snippet echoed `calendar.read` but the mapped
  endpoint had no `.RequireAuthorization` and no scope-policy registration, so it
  would accept ANY valid auth token. FIXED: added `AddAAuthAuthentication()` +
  `AddAAuthAuthorization()` + `AddAAuthScopePolicy("AAuth.Scope.calendar.read",
  "calendar.read")`, `app.UseAuthentication()/UseAuthorization()`, and
  `.RequireAuthorization("AAuth.Scope.calendar.read")` on the endpoint — matching
  the real Calendar server.
- **GAP — Deferred.razor (`/events`):** same gap, same fix.
- **Minor — JwksUri.razor (`/identified`):** identity-mode endpoint omitted the
  real Profile server's `.RequireAuthorization("AAuth.Identified")`. FIXED: added
  the authn registration + `.RequireAuthorization("AAuth.Identified")` so the
  snippet shows that a pseudonymous caller is rejected.
- **OK (no change):** Mission.razor already shows `AddAAuthScopePolicy` +
  `.RequireAuthorization` on both endpoints. Hwk (`/pseudonymous`, no scope),
  Federated (agent + PS code, no resource snippet), CallChain / MissionCallChain
  (client code) have no scope-echoing resource snippet.
- SampleApp builds 0/0. These are displayed `<pre><code>` snippets (HTML text),
  so no behavioral change — only the teaching code now matches the real servers.
