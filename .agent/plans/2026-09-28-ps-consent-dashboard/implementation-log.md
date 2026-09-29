# PS Consent Dashboard — Implementation Log

Append-only. Entries: `[YYYY-MM-DD] [Phase N] <title>` with a status of
`PROCEEDED (default X)`, `BLOCKED`, or `RESOLVED`.

## Decisions taken

### [2026-09-28] [Phase 0] Q1 — Base branch

RESOLVED (owner). Build on `wip/aauth-draft-11`, on top of the in-flight
draft-11 changes. Do not branch from `origin/main`.

### [2026-09-28] [Phase 0] Q2 — Waiting-step UI

RESOLVED (owner).
- The waiting step's primary button opens the PS dashboard, optionally
  deep-linked with `?code=` to highlight the request (see Q12).
- The per-request interaction URL is shown only as a small secondary "or open
  this request directly" link.
- The button is shown only at the waiting step. Clicking it is optional, and
  polling never depends on it.

### [2026-09-28] [Phase 0] Q3 — Sequencing against the red build

PROCEEDED (default: gate on build).
- `dotnet build AAuth.slnx` is red on the branch (23 errors, see research
  §Baseline).
- Phases 1+ start only once MockPersonServer, SampleApp (through AAuth.R3) and
  GuidedTour compile under the draft-11 migration.
- This initiative does not fix draft-11 compile errors. If it must start
  earlier, it may only touch files it already owns and must log each deviation.

### [2026-09-28] [Phase 0] Q4 — Wire response

PROCEEDED (default: keep `requirement=interaction`).
- The PS keeps emitting `url` + `code`.
- The dashboard completes the interaction out-of-band (#user-interaction, v11
  L1011).
- No SDK or wire change. `requirement=approval` is out of scope (see the plan's
  Out of Scope table).

### [2026-09-28] [Phase 0] Q5 — Dashboard authentication and availability

PROCEEDED (default: isolated demo sign-in, same gate as the consent page).
- `GET /dashboard` requires a signed-in person (#ps-approval-endpoint-auth, v11
  L2908).
- Sign-in reuses the isolated demo identity (`isolated-person-demo`) and the
  loopback-only guard. It is enabled exactly when `AAuth:EnableIsolatedDemoConsent`
  is enabled; otherwise the dashboard returns `401`.
- Decisions are POSTs carrying a session cookie plus a CSRF token.
- All requests belong to the single demo person. A real PS resolves the
  agent-to-person binding.

### [2026-09-28] [Phase 0] Q6 — Code consumption on dashboard decision

PROCEEDED (default: `BrowserInteraction.Renew()` under the entry lifecycle gate).
- A dashboard decision renews the code, which retires the old code and bumps
  `Generation` so any in-flight `/interaction` decision is rejected. A later
  visit with the old code gets `invalid_code` (#interaction-code-format, v11
  L2396).
- If tests show `Renew()` has side effects (failed-attempt counting, or a fresh
  code leaking via a later `202`), escalate to an SDK `Consume()` and log a
  deviation.

### [2026-09-28] [Phase 0] Q7 — Live updates

PROCEEDED (default: JSON endpoint + vanilla JS polling).
- `GET /dashboard/requests` returns JSON and the page polls it every ~1 s.
- No SignalR or SSE. The page stays static HTML like the existing consent
  pages.

### [2026-09-28] [Phase 0] Q8 — History scope and retention

PROCEEDED (default: in-memory, capped, reset-aware).
- A sample `ConsentRegistry` records each parked PS consent request and its
  outcome: approved, denied, expired, withdrawn, or delivered.
- It holds a reference to the live entry so status is derived, not copied.
- Capped at 500 records (oldest dropped). Cleared by `/admin/reset`.
- Per mission, the dashboard also links to the existing mission log
  (#interaction-response-poll-authority, v11 L1181).

### [2026-09-28] [Phase 0] Q9 — Request kinds

PROCEEDED (default: list all PS-parked requests; decide only PS-hosted ones).
- **Decidable:** three-party token consent, the out-of-scope mission token gate,
  mission creation, tool permission, and the four-party PS consent step.
- **Listed read-only, with a "complete at the Access Server" link:** Access
  Server interactions relayed by the PS (their `url` is not PS-hosted, v11
  L1011).
- **Not listed:** resource-interaction hops before PS consent.

### [2026-09-28] [Phase 0] Q10 — Scripted mission decisions

PROCEEDED (default: show as history). When `MissionConsentScript` resolves a
prompt without a person (non-interactive mode), the registry records it as
`approved by script` or `denied by script`, so the history matches the mission
log.

### [2026-09-28] [Phase 0] Q11 — Shared agent-side prompt component

PROCEEDED (default: new tiny Razor library `samples/ConsentSupport`).
- It holds a `PersonServerApprovalPrompt` component and a `PersonServerConsent`
  helper, which builds the dashboard URL and classifies whether an interaction
  URL is PS-hosted.
- It is referenced by EventSupport, CapabilitySupport, SampleApp and GuidedTour,
  and added to `AAuth.slnx`.
- Alternative if you prefer no new project: place both in EventSupport (the
  lowest existing shared library).

### [2026-09-28] [Phase 0] Q12 — Deep-link parameter

PROCEEDED (default: `?code=`).
- The dashboard highlights the pending request matching the code.
- The lookup is read-only: it never consumes the code and never counts as a
  failed attempt.
- Unknown codes are ignored silently (no oracle beyond "no highlight").

### [2026-09-28] [Phase 0] Q13 — Playwright strategy

PROCEEDED (default: dashboard-first, keep direct-link coverage).
- Add `approveOnDashboard` and `denyOnDashboard` helpers that open the dashboard
  once per browser context and act on the matching request.
- Migrate PS-hosted consent specs to them.
- Keep one direct-link spec per app for the secondary link, plus a spec proving
  that a dashboard decision makes the old link return `invalid_code`.

### [2026-09-28] [Phase 0] Q14 — CLIs

PROCEEDED (default: dashboard-first).
- MissionAgent opens the dashboard once per run (interactive mode), and for each
  prompt prints `Approve on the PS dashboard: {ps}/dashboard (or directly: {url})`.
- AgentConsole prints both URLs.

### [2026-09-28] [Phase 0] Q15 — Decision-logic sharing

PROCEEDED (default: extract one `PersonConsentDecisions` service).
- Move the mutation bodies of `/interaction/approve` and `/interaction/deny`
  (both stores, asserter call, `FederationConsent`, standing-consent grant) into
  one service used by the link path, the dashboard and the registry.
- Its behaviour must stay byte-for-byte the same for the link path.

### [2026-09-29] [Phase 0] Q3 — Build gate superseded

RESOLVED. Supersedes the 2026-09-28 Q3 entry.
- The draft-11 migration closed (`ecc71e7`).
- `dotnet build AAuth.slnx -c Release` is green at `1045186`.
- The full solution build is now the gate for every phase.
- Research line citations were re-derived after the owner's `e2154a1`
  refactor (research.md §Baseline update).

### [2026-09-29] [Phase 0] Q16 — Sequencing with the SDK API surface plan

RESOLVED (owner): "We will do it next."
- This initiative lands before
  [2026-09-29-sdk-api-surface-consistency](../2026-09-29-sdk-api-surface-consistency/implementation-plan.md),
  which rebases onto it.
- Forward-compatibility rules were added to Guiding principles:
  - DI-registered sample services;
  - no new PS-identity restatements;
  - the prompt takes `Interaction`;
  - no new per-request builders or manual seams;
  - no SDK types.
- The Phase 7 review checks them.

### [2026-09-29] [Phase 0] Scope — GuidedTour capability modes

PROCEEDED (default: include in Phase 4).
- `e2154a1` added GuidedTour capability modes (Events, Wallet Protocol,
  Documents, Catalog) in `TourSession.Capabilities.cs`. Their PS-hosted
  waiting steps (`CapAuthority` L670-L684) get the same poll-on-arrival,
  prompt, and "Run all" behaviour as the classic tracks.

### [2026-09-29] [Phase 0] Q4–Q15 — Owner review of defaults

RESOLVED (owner): "accept". Every default ruling Q4–Q15 stands as recorded
above, including:
- Q6: `Renew()` code consumption, with the SDK `Consume()` fallback logged if
  needed.
- Q9: the dashboard decides PS-hosted requests only.
- Q11: a new `samples/ConsentSupport` library.

Phase 0 is complete.

## Deviations from plan

### [2026-09-29] [Phase 1] Q6 escalated — SDK `BrowserInteraction.Consume()`

RESOLVED (Q6 fallback, as pre-authorised).
- **Why `Renew()` was not enough.** `Renew()` issues a fresh code. In
  four-party, the entry stays `Pending` while federation continues after PS
  consent, and `Pending202` (AAuthPersonServerEndpoints.cs L1566) re-emits
  `entry.Browser.Code`. A dashboard `Renew()` would therefore leak a fresh,
  unconsumed code in the next `202`: exactly the side effect Q6 named.
- **The fix.** A public `BrowserInteraction.Consume()` bumps `Generation`,
  which fails any in-flight page decision, and marks the code consumed, so
  arrivals return `invalid_code`. The code value itself is kept, which
  matches the link path.
- **Tests.**
  - `BrowserConsentSessionTests.ConsumedCodeRejectsOpenDecisionAndNewArrival`.
  - The API map was refreshed. It also picked up the unmapped `e2154a1`
    GuidedTour/TourOptions additions.

### [2026-09-29] [Phase 1] Registry scope details

PROCEEDED.
- A `PersonToken` kind was added, for `/person` identity consent, which the
  plan did not name.
- Four-party entries are listed only once the PS asks for consent
  (`FederationConsent`) or relays an AS interaction. Background federation
  that needs no person decision stays hidden.
- The Delivered status applies only to approvals; a denial stays `Denied`.
- Scripted permission resolutions record `Decision` and `DecidedBy = Script`.
  Automated SDK decisions with no recorded decider display as
  `Script` (mission kinds) or `Policy`.
- The dashboard decision path (`DecideAsync`, which takes the lifecycle gate
  and consumes the code) landed in Phase 1 with its tests, ahead of the
  Phase 2 UI.
- The full Playwright run is deferred to the end of Phase 2. Phase 1 changes
  no UI.

## Open questions / inputs needed

_None yet._
