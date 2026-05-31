# Implementation Plan — Playwright E2E for GuidedTour & SampleApp

Date: 2026-05-31
Companion research: [research.md](research.md)

Deliver Playwright end-to-end tests that exercise every interactive permutation
(dropdowns, buttons, multi-step flows, cross-tab consent) of `samples/GuidedTour`
and `samples/SampleApp`, asserting page content and JSON outputs per page/step.

## Conventions

- Runner: `@playwright/test` (TypeScript). See Phase 0 decision.
- Toolchain root: `tests/e2e/`. Specs live in
  `samples/GuidedTour/playwright-tests/` and
  `samples/SampleApp/playwright-tests/`, wired via `projects[].testDir`.
- Web-first assertions only (`expect(locator).…`); no fixed `sleep`s.
- Each spec waits for the Blazor circuit (interactive) before interacting.

---

## Phase 0 — Toolchain & decisions

Scope: provision Node + Playwright, pin versions, lock the runner and folder
decisions before writing specs.

### Implementation Decisions

- [x] **Runner = `@playwright/test` (TypeScript).** Chosen as planned.
- [x] **Node provisioning:** Node 20 + npm installed via NodeSource in
  `.devcontainer/post-create.sh` (not the devcontainer feature, to keep the
  existing image). Pinned Node `>=20`.
- [x] **Pinned versions:** `@playwright/test` `1.49.1`, `typescript`,
  `@types/node` (see `tests/e2e/package.json`). Chromium Headless Shell.
- [x] **Folder layout:** single toolchain under `tests/e2e/`; specs under each
  sample's `playwright-tests/` referenced by `testDir`. NOTE: spec files import
  helpers via relative paths and runs require `NODE_PATH=./node_modules` (baked
  into npm scripts) because `node_modules` lives only in `tests/e2e/`.

### Files

- `tests/e2e/package.json` — scripts: `test`, `test:tour`, `test:sample`,
  `report`, `install-browsers`.
- `tests/e2e/tsconfig.json`.
- `tests/e2e/.gitignore` — `node_modules/`, `test-results/`, `playwright-report/`.
- `tests/e2e/README.md` — how to run, prerequisites, server lifecycle.
- (optional) `.devcontainer/devcontainer.json` — add Node feature.

### Definition of Done

- [x] `npm install` succeeds in `tests/e2e/`.
- [x] `npx playwright install --with-deps chromium` succeeds.
- [x] Versions pinned and recorded in this section (`@playwright/test 1.49.1`).
- [x] `tests/e2e/README.md` documents prerequisites and run commands.

---

## Phase 1 — Config, server lifecycle, shared helpers

Scope: Playwright config with both projects, backend/app lifecycle, and the
shared helpers all specs depend on. Prove the circuit-wait approach with one
smoke spec.

### Files

- `tests/e2e/playwright.config.ts`:
  - `projects`: `guided-tour` (`testDir:
    ../../samples/GuidedTour/playwright-tests`, `baseURL:
    http://localhost:5400`) and `sample-app` (`testDir:
    ../../samples/SampleApp/playwright-tests`, `baseURL:
    http://localhost:5240`).
  - `webServer` array (one entry per process), `reuseExistingServer: true`:
    - WhoAmI `:5000`, Orchestrator `:5200`, MockAgentProvider `:5301`,
      MockPersonServer `:5100` (env `MockPersonServer__RequireConsent=true`),
      GuidedTour `:5400`, SampleApp `:5240` — each via `dotnet run --project …`.
    - `url` health checks per service (well-known endpoints / home page).
  - `use`: `trace: 'on-first-retry'`, `screenshot: 'only-on-failure'`,
    `video: 'retain-on-failure'`.
  - `timeout` default 30s; deferred specs override to ≥120s.
- `tests/e2e/helpers/blazor.ts`:
  - `waitForInteractive(page)` — wait until the primary action button is
    enabled (canonical circuit-ready signal validated here).
  - `gotoInteractive(page, path)` — navigate + wait interactive.
- `tests/e2e/helpers/consent.ts`:
  - `grantConsent(agent, resource, scope?)`, `revokeConsent(...)` — POST to
    MockPS `/admin/*` via `request` fixture.
  - `approveInPopup(popup)` / `denyInPopup(popup)` — click `button.approve` /
    `button.deny` on the PS interaction page.
- `tests/e2e/helpers/json.ts`:
  - `readResponseJson(locator)` — parse `pre > code.language-json` text.
  - `expectStatus(page, code)` — assert the `.alert` status `<strong>`.
- `tests/e2e/helpers/agents.ts` — known agent ids/resource URLs from
  `appsettings.json` (`aauth:sample-app@localhost:5240`,
  `aauth:tour-agent@localhost:5400`, resource `http://localhost:5000`,
  orchestrator `http://localhost:5200`).
- Smoke spec `samples/GuidedTour/playwright-tests/smoke.spec.ts` — load `/`,
  assert `h1` "AAuth Guided Tour", `select#flow-select` present, circuit
  interactive.

### Definition of Done

- [x] `npx playwright test --project guided-tour smoke` passes (fresh
  `webServer` boot; `reuseExistingServer` when `make demo` already running).
- [x] `waitForInteractive` reliably gates on circuit readiness (validated; see
  research OQ4 — button-enabled == circuit ready).
- [x] Health checks bring all six services up before specs run.
- [x] Helpers compile under `tsc --noEmit`.

---

## Phase 2 — SampleApp specs (per-page, per-permutation)

Scope: one spec file per route; assert page content and every button-driven
output state. Resolve Open Question 1 (`/jwt` consent) during the first smoke
run and adjust.

### Files (`samples/SampleApp/playwright-tests/`)

- `home.spec.ts` — six cards present; each card title, badge set, and `href`
  (`hwk`, `jwks-uri`, `jwt`, `deferred`, `jkt-jwt`, `call-chain`); prerequisites
  section text.
- `hwk.spec.ts` — click Send → `.alert-success` `200`; JSON `scheme == "hwk"`,
  `mode == "pseudonymous"`, `jkt` present. Assert button `Sending...`/disabled
  transient.
- `jwks-uri.spec.ts` — enrol button → enrolled `.alert-info` (local key handle +
  JWKS URI); send → `200` JSON `scheme == "jwks_uri"`, `kid` present.
- `jwt.spec.ts` — pre-grant consent in `beforeEach`
  (`grantConsent(sampleAgentId, resourceUrl)`) per OQ1; send → `200` JSON
  `mode == "three-party"`, `agent`/`sub`/`iss` present.
- `deferred.spec.ts`:
  - approve path: click Send → `_interactionUrl` anchor + `.spinner-border`
    visible; capture popup, `approveInPopup`; assert `.alert-success` `200`,
    JSON `mode == "three-party"`. Per-test timeout ≥120s.
  - deny path: capture popup, `denyInPopup`; assert `.alert-danger` contains
    "user denied".
- `jkt-jwt.spec.ts` — enrol → refresh (ephemeral thumbprint `.alert-success`) →
  send → `200` JSON. Assert durable vs ephemeral thumbprints differ.
- `call-chain.spec.ts` — consent pre-granted by page; send → `200`; JSON shows
  nested `act` chain (Agent → Orchestrator → Resource). Assert chain depth.
- `error-states.spec.ts` (optional) — point one page at a downed dependency to
  assert `.alert-danger` rendering (or skip if too brittle).

### Definition of Done

- [x] All route specs pass against `webServer` backends. Home, hwk, jwks-uri,
  jwt, deferred (approve+deny), jkt-jwt, call-chain: green (9 specs).
- [x] Each non-2xx vs 2xx alert variant asserted where reachable.
- [x] OQ1 resolved: `/jwt` DOES need a pre-grant (`beforeEach` grants
  `(sample-app, resource)`); spec reflects it. See research OQ1.
- [x] Deferred approve AND deny paths both green.
- [x] No fixed sleeps; all assertions web-first.
- [x] **`call-chain` green** — an earlier "SDK hang" diagnosis was wrong. The
  page works end-to-end (rendered `200` + nested `act` chain), confirmed both
  manually via `make demo-sample` and under Playwright. The apparent hang was the
  Blazor cold-circuit first-click drop (call-chain is the first interactive
  SampleApp spec to click its button). Fixed with `clickAndConfirm`; no SDK
  change needed. See research "Call-chain cold-circuit drop".

---

## Phase 3 — GuidedTour specs (dropdown permutations + step engine)

Scope: drive the single page across all flow/signing-mode permutations,
asserting per-step timeline state, payload panels, and the deferred cross-tab
loop.

### Files (`samples/GuidedTour/playwright-tests/`)

- `picker.spec.ts` — option enabled/disabled states match config (Bootstrap
  enabled w/ AP, three-party enabled w/ PS, CallChain needs PS+Orchestrator);
  `signing-mode-select` appears only in Identity; `.flow-picker__desc` text
  changes per selection (Pseudonymous / Agent Identity / Key Rotation).
- `identity.spec.ts` — parameterized over `Hwk | JwksUri | JktJwt`:
  - select Identity + signing mode; `Run all` → `Done`; assert 2 `.step.done`;
    final payload `Response` panel shows `200`; assert `GET /hwk` vs `/jwks-uri`
    path per mode.
- `bootstrap.spec.ts` — select Bootstrap; step through; assert 3 steps (AP set),
  final `TokenView` shows `aa-agent+jwt`. Confirm count per OQ2.
- `autonomous.spec.ts` — select Autonomous; `Run all` → `Done`; assert 6 steps;
  intermediate step shows `401` then `200` exchange then final `200`.
- `deferred.spec.ts` — select Deferred; step until `a.primary.approve` appears;
  click it (captures PS popup), `approveInPopup`; assert `.polling` spinner then
  resolution; `Run step` to final `200`; assert 9 steps, loop label "resolved".
  Per-test timeout ≥120s.
- `deferred-deny.spec.ts` — same up to popup; `denyInPopup`; assert denied step,
  `.error`/loop turns red, run halts.
- `run-all-deferred-stops.spec.ts` — Deferred + `Run all` → assert error banner
  instructs user to open consent link (does not auto-complete).
- `reset.spec.ts` — run some steps, `Reset` → all steps `pending`, payload hint
  "Run a step to see its payloads here.".
- `step-inspector.spec.ts` — click a done `.step`; assert `PayloadInspector`
  shows `SDK code`, `Request`, `Response`; signature-base `<details>` present.

### Definition of Done

- [x] All five flows reach `Done` (or expected halt) with correct step counts
  (Bootstrap 3, Identity 2, Autonomous 6, Deferred 9, CallChain 7).
- [x] All three Identity signing modes asserted (200 + reported scheme:
  `hwk` / `jwks_uri` / `jkt-jwt`).
- [x] Deferred approve + deny paths green (granting consent dynamically via the
  PS consent URL in a real popup, not the admin backdoor). `Run all` stop
  behaviour exercised implicitly (the helper parks on the consent link).
- [x] Reset and step-inspection specs green (combined in `reset.spec.ts`).
- [x] OQ2 resolved: bootstrap = 3 steps with AP configured; asserted.

NOTE on file layout vs plan: implemented as `picker.spec.ts`, `identity.spec.ts`
(3 cases), `bootstrap.spec.ts`, `autonomous.spec.ts`, `deferred.spec.ts`
(approve+deny in one describe), `reset.spec.ts` (reset + step inspector), and
`call-chain.spec.ts` (7-step multi-agent flow → three-party 200 + nested `act`
chain, plus the decoded chain summary on the inspect step).

Result assertions (DoD per user): every result-bearing spec asserts the actual
on-page rendered status (`200`) plus a representative claim/scheme from the
Response panel — not merely that the flow ran.

---

## Phase 4 — Make targets, docs, CI wiring

Scope: make the suite runnable via `make` and (optionally) CI.

### Files

- `Makefile` — add:
  - `e2e-install` — `cd tests/e2e && npm ci && npx playwright install --with-deps chromium`.
  - `e2e` — boot backends (reuse `demo`/`demo-sample` logic or rely on
    `webServer`) and run `npx playwright test`.
  - `e2e-tour` / `e2e-sample` — per-project runs.
  - `e2e-report` — `npx playwright show-report`.
- `tests/e2e/README.md` — finalize: prerequisites, `make e2e*`, trace viewing,
  reuse-vs-fresh server behavior, deferred-path notes.
- (optional) `.github/workflows/e2e.yml` — install .NET + Node + browsers, run
  `make e2e`, upload `playwright-report/` artifact. Gate on `workflow_dispatch`
  first if CI minutes are a concern.

### Definition of Done

- [x] `make e2e-install` provisions toolchain + browsers from clean.
- [x] `make e2e` runs both projects green (fresh boot via `webServer`).
- [x] `make e2e-tour` / `make e2e-sample` run subsets.
- [x] README documents the full workflow (`make e2e*`, NODE_PATH note,
      reuse-vs-fresh servers, deferred + call-chain notes, traces).
- [x] CI workflow — implemented as a gated `e2e` job in
      `.github/workflows/ci.yml` (`needs: build`): sets up .NET 10 + Node 20,
      installs deps + Chromium, runs `npm test`, uploads the HTML report
      artifact.

---

## Phase 5 — Deep content assertions across every spec

Scope: every result-bearing spec must assert the FULL meaningful content of the
rendered payload — exact claim values and structure — not merely that a field or
substring exists. Shallow checks (`toContain('act')`, `typeof x === 'string'`,
`toBeTruthy()`) are replaced with exact-value assertions tied to the known
demo identities, schemes, issuers, scopes, and (where applicable) the nested
`act` delegation chain.

### Known response shapes (source of truth)

WhoAmI (`samples/WhoAmI/Program.cs`):

- `/hwk` → `{ mode: "pseudonymous", scheme: "hwk", jkt: <thumbprint>, note }`.
- `/jkt-jwt` → `{ mode: "pseudonymous", scheme: "jkt-jwt", jkt, note }`.
- `/jwks-uri` → `{ mode: "agent-identity", scheme: "jwks_uri", jwks_uri, kid, note }`.
- `/` (three-party) → `{ mode: "three-party", scheme: "jwt", agent, sub: "pairwise-sub",
  scope: ["whoami"], iss: "http://localhost:5100", act: { sub: <agent> } }`.

MockPersonServer (`samples/MockPersonServer/Program.cs`): auth tokens carry
`sub: "pairwise-sub"`, `scope: "whoami"`, `iss: http://localhost:5100`. The
`act` claim is `{ sub: <immediate agent> }`, nesting `act.act` for each upstream
hop (`AuthTokenBuilder` clones `UpstreamAct`).

Call-chain combined payload (`Orchestrator`): `{ upstream: { scheme, agent, tokenType },
orchestrator: { identity, action }, downstream: { mode: "three-party", scheme:
"jwt", agent: <orchestrator>, sub, scope, iss, act: { sub: <orchestrator>, act:
{ sub: <calling agent> } } } }`.

### Files

- `tests/e2e/helpers/json.ts` — keep `readResponseJson` (already parses the
  rendered `pre code.language-json`). No structural change needed.
- `tests/e2e/helpers/tour.ts` — add `readResponseJson(page)` for the GuidedTour
  inspector Response panel (parse the rendered JSON from `pre code`), so tour
  specs can assert exact structure rather than substrings via `expectResponse`.
- SampleApp specs (`hwk`, `jwks-uri`, `jwt`, `jkt-jwt`, `deferred`, `call-chain`)
  — replace `toBeTruthy()` / `typeof` checks with exact values: `mode`, `scheme`,
  the resource `iss`/`sub`/`scope`, and the `act` chain where present.
- GuidedTour specs (`identity`, `autonomous`, `deferred`, `call-chain`,
  `bootstrap`) — parse the inspector Response (or token) panel and assert exact
  claim values and the `act` chain, not `toContainText` substrings.

### Definition of Done

- [x] No result-bearing spec relies on `toContain`/`toContainText` of a lone
  claim name, `toBeTruthy()`, or `typeof === 'string'` as its only check on a
  meaningful field. Each asserts the exact expected value.
- [x] Every three-party spec asserts `sub`, `scope`, `iss`, and the `act.sub`
  (and nested `act.act.sub` for call-chain).
- [x] Identity specs assert the exact `mode` + `scheme` per signing mode, and a
  present `jkt`/`kid` value where the resource returns one.
- [x] GuidedTour result assertions parse the rendered inspector JSON and assert
  structure, mirroring the SampleApp depth.
- [x] `tsc --noEmit` clean; `make e2e` green (both projects, 0 skipped).

---

## Phase 6 — Address PR #28 review feedback

Scope: act on the valid findings collated in `research.md` ("PR #28 review
findings"). Two reviewers (GitHub Copilot + local PR Review subagent) converged
on boundary error handling, selector determinism, dead-code removal, and CI
hardening. This phase covers only the findings tagged **Valid** (plus the two
**Partially valid · Medium** robustness items) and the consent-reset isolation
fix (adopted as a core PS change — see research "Test isolation"). The PS
admin-endpoint gating is explicitly deferred (see research doc rationale).

### Files

- `samples/MockPersonServer/ConsentStore.cs` — add `Clear()` to `ConsentStore`
  and `Clear()` to `PendingStore` (wipe all entries back to baseline).
- `samples/MockPersonServer/Program.cs` — add a demo-only
  `POST /admin/reset` endpoint that calls `ConsentStore.Clear()` +
  `PendingStore.Clear()` and returns `{ ok = true }`.
- `tests/e2e/helpers/consent.ts` — make `grantConsent` capture the response and
  throw on non-OK (status + body); remove the unused `revokeConsent`; add a
  `resetConsent(request)` helper that POSTs `/admin/reset` and throws on non-OK.
- `tests/e2e/helpers/fixtures.ts` (new) — extend Playwright's `test` with a
  `consentReset` auto-fixture that calls `resetConsent` before every test; all
  spec files import `test`/`expect` from here instead of `@playwright/test` so
  each spec starts hermetic.
- `tests/e2e/helpers/tour.ts` — remove the unused `readTokenJson`; tighten the
  `runAll` wait to a single unambiguous locator; scope `expectResponse`'s status
  check to the status line (or `\b<status>\b`).
- `tests/e2e/helpers/json.ts` — remove unused `successAlert`; scope
  `expectStatus` to avoid bare-substring false matches.
- `tests/e2e/helpers/blazor.ts` — remove unused `gotoInteractive`.
- `tests/e2e/helpers/agents.ts` — remove unused `Agents.sampleAppEnrolled`,
  `Urls.guidedTour`, `Urls.sampleApp`.
- `tests/e2e/package.json` — add `"engines": { "node": ">=20" }`.
- `.github/workflows/ci.yml` — cache `~/.cache/ms-playwright` keyed on the
  resolved Playwright version; also upload `tests/e2e/test-results` on failure.

### Definition of Done

- [x] `grantConsent` throws on non-OK admin responses with status + body in the
  message; `resetConsent` does likewise.
- [x] PS exposes `POST /admin/reset`; `ConsentStore.Clear()` +
  `PendingStore.Clear()` wipe state; a global `beforeEach` (the `consentReset`
  auto-fixture in `tests/e2e/helpers/fixtures.ts`) resets before each spec so
  the suite is hermetic regardless of spec order.
- [x] No unused exports remain in `tests/e2e/helpers/` (`readTokenJson`,
  `successAlert`, `gotoInteractive`, `revokeConsent` removed,
  `Agents.sampleAppEnrolled`, `Urls.guidedTour`, `Urls.sampleApp`).
- [x] `runAll` waits on a single deterministic locator; `expectResponse` /
  `expectStatus` no longer match a bare `200` substring.
- [x] `package.json` declares a Node engine floor; CI caches the Playwright
  browser binaries and uploads `test-results/` on failure.
- [x] `tsc --noEmit` clean; `make e2e` green (both projects, 0 skipped).
- [ ] Deferred (NOT in this phase): gating the PS `/admin/*` endpoints behind
  `IsDevelopment()`.

---

## Out of scope

| Item | Reason |
|---|---|
| Visual regression / pixel snapshots of the SequenceDiagram SVG | High maintenance; assert structural content instead |
| Testing the other samples (WhoAmI, AgentConsole, Orchestrator, MockServers) directly | They are backends/CLI, not browser UIs; covered indirectly |
| Cross-browser matrix (Firefox/WebKit) | Start Chromium-only; add later if needed |
| Load/perf testing of the deferred poll loop | Functional E2E only |
| Replacing existing xUnit conformance/unit tests | Complementary, not a replacement |
| Mobile viewport / responsive testing | Not a stated requirement |
