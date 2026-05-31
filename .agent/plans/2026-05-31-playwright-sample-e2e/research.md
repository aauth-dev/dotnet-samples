# Research — Playwright E2E for GuidedTour & SampleApp

Date: 2026-05-31
Status: Research only (no task lists here — see `implementation-plan.md`).

## Goal

Introduce browser end-to-end (E2E) tests driven by Playwright that exercise
every interactive permutation of the two Blazor Server demo apps:

- `samples/GuidedTour` (single-page, mode/signing-mode dropdowns, step engine).
- `samples/SampleApp` (multi-page, one routed page per signing mode/flow).

Tests must assert page content, dropdown permutations, button-driven step
outputs, JSON response bodies, and the cross-tab deferred-consent path.

## Apps under test

### GuidedTour (port 5400)

- Single route `/` rendered with `@rendermode InteractiveServer` (Blazor
  Server over a SignalR circuit). Source: `samples/GuidedTour/Components/Pages/Tour.razor`.
- Controls and their stable selectors:
  - `select#flow-select` — five `<option>`s; some disabled by config:
    - `Bootstrap` — disabled unless `HasAgentProvider` (AP URL set).
    - `Identity` — always enabled.
    - `Autonomous` (Direct Grant) — disabled unless `HasPersonServer`.
    - `Deferred` — disabled unless `HasPersonServer`.
    - `CallChain` — disabled unless `HasPersonServer && HasOrchestrator`.
  - `select#signing-mode-select` — only rendered when `flow-select == Identity`;
    options `Hwk`, `JwksUri`, `JktJwt`.
  - `button.primary` — label cycles `Run step N / Total`, then `Done`.
  - `a.primary.approve` (`Open consent page ↗`) — replaces the primary button
    only when `Session.AwaitingUserApproval` (deferred path); `target=_blank`.
  - `button` "Run all", `button` "Reset".
- Output regions:
  - `.flow-picker__desc` — per-mode narrative text (changes with dropdowns).
  - `aside.steps .step-list .step` — planned timeline; each `.step` has
    `.step__pill` (✓ when done / number when pending), `.step__title`,
    `.step__desc`, `.step__actor`. Step classes: `done` / `current` / `pending`.
  - `section.diagram` — `SequenceDiagram` SVG/markup; lanes vary by mode.
  - `section.payload` — `PayloadInspector` with `<details>` panels: `SDK code`,
    `Request`, `RFC 9421 signature base`, `Response`, plus `TokenView`.
  - `header .error` and `.flow-picker` error `div.error` for failures.
  - `section.polling` (`.polling__spinner`, `.polling__title`, poll count) while
    deferred poll loop runs.
- Step counts per mode (from `samples/GuidedTour/README.md`):
  - Bootstrap: 2 (local self-sign) or 3 (real AP enrol — AP URL set ⇒ 3).
  - Identity: 2 (any signing mode).
  - Autonomous (Direct Grant): 6.
  - Deferred: 9.
  - CallChain: 7.
- Mode/signing-mode changes RESET the timeline (`Session.Mode` / `SigningMode`
  setters clear steps) and re-sync PS consent state via
  `PrepareConsentStateAsync()`.

### SampleApp (port 5240)

- Multi-page, `@rendermode InteractiveServer`. Routes:
  - `/` — `Home.razor`: six Bootstrap cards linking to the demos.
  - `/hwk` — `Hwk.razor`: single `button.btn-primary` "Send Signed Request".
    2-party; needs only WhoAmI.
  - `/jwks-uri` — `JwksUri.razor`: two-step — "1. Enrol with Agent Provider"
    (`button.btn-outline-secondary`) then "2. Send Signed Request"
    (`button.btn-primary`). Needs AP + WhoAmI.
  - `/jwt` — `Jwt.razor`: single "Send Signed Request"; 3-party direct grant.
    Needs PS + AP + WhoAmI. (Page does NOT pre-grant; relies on standing
    consent — see Open Questions.)
  - `/deferred` — `Deferred.razor`: calls `/admin/revoke` first, then "Send
    Signed Request"; surfaces `_interactionUrl` anchor (`target=_blank`) and
    polls (`.spinner-border`, `(@_pollCount polls)`). Needs PS (RequireConsent)
    + WhoAmI.
  - `/jkt-jwt` — `JktJwt.razor`: three steps — "1. Enrol", "2. Two-Key Refresh",
    "3. Send Signed Request". Needs AP + WhoAmI.
  - `/call-chain` — `CallChain.razor`: calls `/admin/consent` first, then "Send
    Chained Request". Needs PS + AP + Orchestrator + WhoAmI.
- Output regions (consistent across pages):
  - Response block: `div.alert.alert-success` (2xx) or `div.alert.alert-warning`
    (non-2xx) containing `<strong>{status} {reason}</strong>`, followed by
    `pre > code.language-json` with the pretty-printed JSON body.
  - Errors: `div.alert.alert-danger` with the exception message.
  - Loading state: button text flips to `Sending...` and is `disabled`.
  - Page title via `<PageTitle>` (per-page, e.g. "HWK — Pseudonymous").

## Dependency topology (from `Makefile`)

| Service | Project | Port | Needed by |
|---|---|---|---|
| WhoAmI (resource) | `samples/WhoAmI` | 5000 | all flows |
| MockPersonServer | `samples/MockPersonServer` | 5100 | jwt, deferred, call-chain, autonomous |
| Orchestrator | `samples/Orchestrator` | 5200 | call-chain |
| MockAgentProvider | `samples/MockAgentProvider` | 5301 | jwks-uri, jkt-jwt, bootstrap enrol |
| GuidedTour | `samples/GuidedTour` | 5400 | tour specs |
| SampleApp | `samples/SampleApp` | 5240 | sample-app specs |

- `make demo` boots WhoAmI + Orchestrator + MockPersonServer
  (`RequireConsent=true`) + MockAgentProvider + GuidedTour.
- `make demo-sample` boots the same backends + SampleApp.
- **Key fact:** deferred/user-consent paths require
  `MockPersonServer__RequireConsent=true`. Both demo targets already set it.
- All URLs are plain `http://localhost:<port>` (no HTTPS dev-cert friction).

### Consent control surface (MockPersonServer, demo-only)

Source: `samples/MockPersonServer/Program.cs`.

- `POST /admin/consent` `{agent, resource, scope?}` — grant standing consent.
- `POST /admin/revoke` `{agent, resource, scope?}` — revoke (forces deferred).
- `GET /interaction?code={id}` — HTML consent page with two forms:
  - `form[action="/interaction/approve"]` → `button.approve` ("Approve").
  - `form[action="/interaction/deny"]` → `button.deny` ("Deny").
  - hidden `input[name=code]`.
- `GET /pending/{id}` — agent poll target: `202` pending / `200 {auth_token}` /
  `403 access_denied` (denied).
- SampleApp pages self-manage consent: `Deferred.razor` calls `/admin/revoke`,
  `CallChain.razor` calls `/admin/consent`, before each run. The GuidedTour
  manages consent through `TourSession.PrepareConsentStateAsync()`.

## Blazor Server testing constraints (critical)

- **Interactive circuit gate.** With `InteractiveServer`, the page first renders
  static HTML; buttons/`@onchange` handlers only work after the SignalR circuit
  connects and the component re-renders interactively. Playwright must wait for
  interactivity, not just `domcontentloaded`. Practical signals:
  - Wait for the primary button to become enabled (`:not([disabled])`).
  - Or wait for the Blazor `blazor-reconnect`/circuit; simplest robust approach
    is `await expect(button).toBeEnabled()` before clicking.
- **No client-side routing assumptions.** SampleApp uses real navigations
  between pages (`<a href>`), each its own circuit. Navigate per page.
- **State changes are server-pushed.** After clicking, results stream over the
  circuit — use Playwright web-first assertions (`toBeVisible`, `toHaveText`)
  which auto-retry, not fixed sleeps.
- **Deferred cross-tab.** The `target=_blank` consent link opens a new page.
  Playwright captures it via `context.waitForEvent('page')` (popup). After
  clicking `button.approve` there, the original page's poll loop resolves and
  the success alert appears.
- **`Run all` cannot auto-approve.** In the GuidedTour deferred mode, `Run all`
  stops with an error banner asking the user to click the green consent link —
  so the deferred happy path must be driven step-by-step + cross-tab approve.

## Runner options & recommendation

Node.js / npm are **not installed** in the dev container (`node --version`
empty); `.NET 10.0.300` SDK is present. Two viable runners:

| Option | Pros | Cons |
|---|---|---|
| **A. `@playwright/test` (TypeScript)** — recommended | Canonical Playwright DX: trace viewer, codegen, projects/permutation matrix, `webServer`, auto-wait assertions, parallel sharding | Adds a Node toolchain to a .NET repo; browsers + Node must be provisioned |
| **B. `Microsoft.Playwright` (.NET, xUnit/NUnit)** | Stays in `dotnet test` + existing CI/Makefile; no Node install; browsers installed via bundled `playwright.ps1` | Less ergonomic for large permutation matrices; weaker trace/codegen workflow; more boilerplate |

**Recommendation: Option A (TypeScript `@playwright/test`).** The task is
explicitly about analyzing *dropdown permutations, output, and page content* —
Playwright Test's projects/parameterized specs, web-first assertions, popup
handling, and trace viewer are materially better for this. The Node toolchain
cost is one-time and confinable to the test folders. Option B remains the
fallback if the repo must avoid Node entirely (recorded as a decision point in
the plan).

## Folder layout decision

User asked for tests inside sample-specific folders. Chosen layout keeps specs
beside each sample while sharing one toolchain install:

```
tests/e2e/                      # single Node toolchain root
  package.json
  playwright.config.ts          # two projects: guided-tour, sample-app
  global-setup.ts               # boot backends + apps, health-wait
  global-teardown.ts
  helpers/                      # blazor-wait, consent, json-assert helpers
samples/GuidedTour/playwright-tests/   # tour specs (referenced by config testDir)
samples/SampleApp/playwright-tests/    # sample-app specs (referenced by config testDir)
```

Playwright `projects[].testDir` can point at the per-sample folders, so the
specs physically live "inside the sample folders" while config + node_modules
live once under `tests/e2e/`. (If strict isolation is preferred, each sample
folder can instead carry its own `package.json` + config — recorded as an
alternative in the plan.)

## Server lifecycle strategy

- Preferred: Playwright `webServer` array with `reuseExistingServer: true` so a
  developer who already ran `make demo`/`make demo-sample` reuses them, and CI
  boots them fresh. Each backend is a separate `webServer` entry with a
  `url` health check (e.g. `http://localhost:5000/.well-known/aauth-resource.json`).
- Alternative: a `global-setup.ts` that spawns `make demo` / `make demo-sample`
  and polls health endpoints. `webServer` is cleaner and gives per-process
  readiness; use it as primary.
- The two app projects cannot both bind their backends twice — share the four
  backends across both Playwright projects (start once), and start GuidedTour
  (5400) + SampleApp (5240) both (different ports, no conflict). PS must run
  with `RequireConsent=true`.

## Permutation matrix to cover

### GuidedTour

| Flow | Signing mode | Steps | Notes / assertions |
|---|---|---|---|
| Identity | Hwk | 2 | `GET /hwk` → 200; payload shows hwk; desc mentions "Pseudonymous" |
| Identity | JwksUri | 2 | `GET /jwks-uri` → 200; desc "Agent Identity" |
| Identity | JktJwt | 2 | naming-JWT path; desc "Key Rotation" |
| Bootstrap | n/a | 3 (AP set) | keygen + discover + enrol; token panel shows `aa-agent+jwt` |
| Autonomous | n/a | 6 | 401 → exchange 200 → retry 200; no popup |
| Deferred | n/a | 9 | step to 202; popup approve; poll resolves; final 200 |
| Deferred (deny) | n/a | — | popup deny → loop turns red, denied step recorded |
| Run all | Identity/Autonomous | — | drives to `Done`; deferred `Run all` stops with banner |
| Reset | any | — | timeline clears to all-pending |
| Disabled options | n/a | — | assert option disabled-state matches config |

### SampleApp

| Page | Steps | Key assertions |
|---|---|---|
| `/` Home | — | six cards + correct hrefs + badges |
| `/hwk` | 1 | success alert 200; JSON has `scheme: "hwk"`, `jkt` |
| `/jwks-uri` | 2 | enrol → enrolled alert; send → 200 `scheme: "jwks_uri"` |
| `/jwt` | 1 | 200 `mode: "three-party"`; needs standing consent (see OQ) |
| `/deferred` | 1+popup | revoke → 202 → popup approve → 200 `mode: three-party` |
| `/deferred` (deny) | 1+popup | popup deny → `alert-danger` "user denied" |
| `/jkt-jwt` | 3 | enrol → refresh (ephemeral thumbprint) → 200 |
| `/call-chain` | 1 | consent pre-granted → 200 nested `act` chain in JSON |

## Gaps & Open Questions

1. **`/jwt` standing consent.** `Jwt.razor` does not pre-grant consent; with
   `RequireConsent=true` the SDK may hit the deferred path (interaction
   required) and the page has no interaction UI → it could hang/timeout. Need to
   verify behavior at runtime; the test may need to pre-grant via
   `POST /admin/consent` in a `beforeEach`, or run that one spec against a PS
   with consent already granted. **Action: confirm during Phase 2 smoke run.**
   **RESOLVED:** `/jwt` DOES need a pre-grant. `jwt.spec.ts` grants
   `(aauth:sample-app@localhost:5240, http://localhost:5000)` in `beforeEach`
   via `POST /admin/consent`; without it the page has no interaction UI and the
   request never resolves.
2. **Bootstrap step count.** README says 2 (self-sign) or 3 (real AP). With AP
   URL configured (demo default), expect 3. Confirm at runtime.
   **RESOLVED:** 3 steps with the AP URL configured (demo default); asserted in
   `bootstrap.spec.ts`.
3. **Deferred timing budget.** SampleApp deferred polls up to 2 min; GuidedTour
   up to 5 min. Playwright default per-test timeout (30s) is too short — raise
   per-spec timeout for deferred specs.
   **RESOLVED:** deferred specs use `test.describe.configure({ timeout: 150_000 })`
   and per-assertion timeouts of 120s on the poll-resolution wait.
4. **Circuit readiness signal.** Decide the canonical "interactive" wait helper
   (button-enabled vs. Blazor JS hook). Validate empirically in Phase 1.
   **RESOLVED:** button-enabled (`waitForInteractive` → `expect(button)
   .toBeEnabled()`) is the canonical signal. CAVEAT: the very FIRST interactive
   event on a freshly-connected circuit can still be silently dropped (the
   circuit accepts input slightly before it dispatches it). This bit the first
   clicking test in the SampleApp suite (deferred-approve). Fix:
   `clickAndConfirm()` in `helpers/blazor.ts` clicks, polls for a caller-supplied
   "landed" signal, and re-clicks if the event was dropped. For the GuidedTour
   `selectFlow`, the equivalent fix is `toPass()`-retrying the `selectOption`
   until the server-rendered step list reflects the new flow's plan length
   (the `<select>` uses one-way Blazor binding so the DOM value updates before
   `Session.Mode` does, and a cold-circuit change event can be reverted by the
   async on-init consent prep). The same drop affects `selectStep` after
   `runAll`: clicking a non-final step can be dropped, moving the client-side
   selection highlight while the server inspector stays on the auto-selected
   final step. Fix: `selectStep` retries the click via `toPass()` until the
   inspector `h2` (rendered as `"<Number>. <Title>"`) reflects the target step.
5. **CI provisioning.** Whether CI installs Node + browsers (`npx playwright
   install --with-deps`) and how the dev container should pre-install them
   (devcontainer feature vs. Makefile target). Decide in Phase 0/4.
   **RESOLVED (local):** Node 20 + npm are installed via NodeSource in
   `.devcontainer/post-create.sh`; browsers via `make e2e-install`
   (`npx playwright install --with-deps chromium`). CI workflow remains
   optional/out of scope.
6. **Highlight.js / `highlightCode` JS.** Pages call `JS.InvokeVoidAsync(
   "highlightCode")` in `OnAfterRenderAsync`; ensure the wwwroot JS exists so
   the circuit doesn't error. Verify asset present.
   **RESOLVED:** harmless — the inline highlighter is a no-op when the JS is
   absent; no circuit error observed and all result assertions pass.

## Findings (implementation)

- **`NODE_PATH` workaround (toolchain layout).** Spec files live under
  `samples/*/playwright-tests/` but `node_modules` exists only in `tests/e2e/`.
  Direct `npx playwright test` invocations must run from `tests/e2e/` with the
  `NODE_PATH=./node_modules` prefix so the spec files resolve `@playwright/test`.
  This is baked into the `tests/e2e/package.json` scripts and the `make e2e*`
  targets; it only matters for ad-hoc CLI runs.
- **Title-grep, not filename.** `npx playwright test <filename>` mis-parses the
  positional arg as a project filter under this layout; use `-g "<title grep>"`
  to select specs.
- **Logging level to capture the HTTP flow.** `appsettings.json` pins
  `Microsoft.AspNetCore` to `Warning`, which suppresses request logging. To trace
  the protocol during debugging, override BOTH
  `Logging__LogLevel__Default=Information` AND
  `Logging__LogLevel__Microsoft.AspNetCore=Information`. Playwright `webServer`
  stdout is unreliable for runtime logs (servers are reused across runs and
  output is buffered) — start backends manually with per-server log files when
  deep-tracing.
- **WhoAmI JSON shapes (per signing mode), used in result assertions.**
  `/hwk` → `{mode:pseudonymous, scheme:hwk, jkt}`;
  `/jkt-jwt` → `{mode:pseudonymous, scheme:jkt-jwt}`;
  `/jwks-uri` → `{mode:agent-identity, scheme:jwks_uri, kid}`;
  `/` (three-party) → `{mode:three-party, agent, sub, scope, iss, act}`.
- **Call-chain cold-circuit drop (SampleApp `/call-chain`).** The page exchanges
  Agent → Orchestrator → WhoAmI and works correctly end-to-end (rendered `200` +
  nested `act` delegation chain in the payload), as confirmed both manually via
  `make demo-sample` and under Playwright. An earlier investigation wrongly
  attributed an apparent "hang" to a sample/SDK defect; the real cause was the
  Blazor **cold-circuit first-click drop** — `/call-chain` is the first
  interactive SampleApp spec to click its button, so the freshly connected
  SignalR circuit silently discarded the very first click and the request never
  started (the page stayed in its initial state, never reaching "Sending…").
  Fixed by using `clickAndConfirm` (re-click until the handler fires), the same
  helper used for the deferred-approve flake. No SDK change was needed; the spec
  runs as a normal `test` and asserts the rendered `200` plus the nested `act`
  chain.

## Source references

- `samples/GuidedTour/Components/Pages/Tour.razor` — dropdowns, buttons, regions.
- `samples/GuidedTour/Components/StepList.razor`, `PayloadInspector.razor`.
- `samples/GuidedTour/README.md` — flow/step descriptions.
- `samples/SampleApp/Components/Pages/*.razor` — per-page controls/outputs.
- `samples/MockPersonServer/Program.cs` — consent/interaction endpoints + HTML.
- `Makefile` — `demo`, `demo-sample`, per-service ports.
