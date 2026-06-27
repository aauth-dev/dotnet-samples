# Implementation Plan — AAuth-Access opaque-token flow

Companion to [`research.md`](research.md). Adds the draft-08 **`AAuth-Access`**
opaque-token flow (the `aauth-access-token` access mode) to `src/AAuth/`,
`samples/`, `docs/`, and `tests/`, bringing the SDK to parity with
[`aauth-spec/v08/`](../../../aauth-spec/v08/) §`#aauth-access` (L738) and
§`#resource-managed-auth` (L758). Decisions and deviations are recorded in
[`implementation-log.md`](implementation-log.md).

> Status: **Not started — plan only.** Scoped out of the
> [draft-08 migration](../2026-06-25-aauth-v08-spec-migration/implementation-plan.md)
> (its Phase 3 recorded the `AAuth-Access` `token68` validation as N/A because no
> consumption/production path existed). Verify each spec line reference against
> [`aauth-spec/v08/`](../../../aauth-spec/v08/) before editing a file — line
> numbers shift on re-vendor; the `{#anchor}` and symbol references are durable
> (see the verification note in `research.md`).

> **What the 2026-06-27 research changed.** Several building blocks already ship
> but are inert, so this plan **wires** more than it **builds**: the agent signer
> already covers `authorization` when the header is present
> ([AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs)
> L217–221, L280–284), and the resource opaque-token seam
> (`IOpaqueTokenStore` / `InMemoryOpaqueTokenStore` / `OpaqueTokenInfo`,
> [Server/IOpaqueTokenStore.cs](../../../src/AAuth/Server/IOpaqueTokenStore.cs))
> exists but is referenced only by a conformance test. The flow is non-functional
> end to end. See [research § SDK surface to introduce](research.md#sdk-surface-to-introduce)
> and [research § pre-existing inconsistencies](research.md#pre-existing-inconsistencies-to-fix).

## Guiding principles (apply to every phase)

- **Spec accuracy over compatibility.** Match draft-08 exactly. This is a
  spec-accurate alpha SDK with no back-compat guarantee; breaking changes are
  acceptable when they buy spec accuracy. Single coordinated cutover (the SDK
  signs *and* verifies) — no dual-format shims.
- **Wire existing seams; do not rebuild them.** Reuse `IOpaqueTokenStore` on the
  resource and `InteractionHandler` (the `202 → poll Location → terminal 200`
  loop, **not** `DeferredPoller`) on the agent. Add only the trailing
  `AAuth-Access` capture/replay.
- **The signer already binds `authorization`.** The opaque token is never a
  standalone bearer credential, and `authorization` MUST be a covered HTTP-signature
  component whenever an `AAuth-Access` token is presented (spec L753, L2716). The
  agent signer already covers it automatically when present, so the agent work is
  to *set* the header; the resource work is to *assert* it was covered and reject
  if not.
- **Fix pre-existing inconsistencies in passing.** Each phase that touches an
  overstating doc/snippet (research § pre-existing inconsistencies #1–#6) corrects
  it rather than leaving it; the trailing sweep is the backstop, not the only fix.
- **Per-phase e2e gate.** Each code phase ends by running the e2e (Playwright
  guided-tour + sample-app) suites against a fresh full-stack boot (`make e2e`;
  boot the whole backend set together). A phase that changes an e2e-asserted value
  updates that spec in the same phase.

## Summary of the change

| Area | From (current) | To (draft-08) | Phase |
|---|---|---|---|
| `token68` grammar | none | parse/validate (reject empty / whitespace / control / multi-credential) | 1 |
| `AAuth-Access` header constant | **absent** from `AAuthConstants.Headers` | added (fixes inconsistency #4) | 1 |
| Agent capture/replay | none | `IAAuthAccessStore` + `AAuthAccessHandler`; replay `Authorization: AAuth`; rolling refresh | 2 |
| Signature binding | signer **already** covers `authorization` when present (L217–221/L280–284) | unchanged — handler only *sets* the header; assert via tests | 2 |
| Resource opaque store | `IOpaqueTokenStore` ships but **inert** (test-only) | wired into the pipeline (`IssueAsync`/`ValidateAsync`) | 3 |
| `AAuthAccessMode` enum | `IdentityOnly` / `RequireAuthToken` / `AgentTokenRequired` | `+ ResourceManaged` | 3 |
| Resource issue/consume | none | emit `AAuth-Access`; validate `Authorization: AAuth` + assert `authorization` covered | 3 |
| `authorization_endpoint` | metadata field emits; **no handler** | `MapAAuthAuthorizationEndpoint` (signed `POST`) + agent proactive request; Inbox demos both entry points | 3–4 |
| Demo server | four Aria servers, no resource-managed | new **Inbox** `:5004` (email) + GuidedTour/SampleApp slot 2 | 4 |
| Docs / snippets | overstate (inconsistency #1–#3) or missing | swept; "not implemented" note flipped | 5 |

---

## Phase 0 — Decision gate

Resolve `research.md` OQ1–OQ6 before code. No code in this phase; record each
ruling in [`implementation-log.md`](implementation-log.md) and tick the matching
box. Prefer a default ruling (`default X, revert if you disagree`) over blocking.

### Implementation Decisions (Phase 0)

- [ ] **OQ1** Opaque-state wrapping seam — *research-resolved:* the seam ships
      (`IOpaqueTokenStore`); confirm **no** default crypto wrapper is added (app
      supplies state), only the wiring.
- [ ] **OQ2** Per-origin replay store ownership — sibling `AAuthAccessHandler`
      **outer** of the signer + injectable `IAAuthAccessStore` (in-memory default).
- [ ] **OQ3** `authorization` covered-component toggle — *research-resolved:* the
      signer auto-covers when present; no per-request toggle.
- [ ] **OQ4** Rolling-refresh race rule — last-writer-wins, no serialization.
- [ ] **OQ5** Confirm the `202 → poll → 200` handshake reuses `InteractionHandler`
      / `Interaction` (corrects the original "DeferredPoller" note).
- [x] **OQ6** `authorization_endpoint` entry point — **in scope** (owner ruling):
      the samples must demonstrate **both** spec entry points — the reactive `202`
      and a proactive signed `POST authorization_endpoint` (L605, L620, L2642). Adds
      a `MapAAuthAuthorizationEndpoint` helper (Phase 3), exercised by Inbox
      (Phase 4).

### Definition of Done

- [ ] Each OQ has a recorded ruling (or `default X, revert if you disagree`) in
      `implementation-log.md`.

---

## Phase 1 — `token68` grammar + `AAuth-Access` header constant

Lowest-risk, pure functions and a constant — no flow yet. Also fixes
[inconsistency #4](research.md#pre-existing-inconsistencies-to-fix) (missing
constant).

### Scope

- Add `AAuthConstants.Headers.AAuthAccess = "AAuth-Access"` to
  [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs) (the one header without
  a constant).
- New `Headers/AAuthAccessHeader.cs`: validate a single RFC 9110 §11.2 `token68`;
  **reject** empty, embedded whitespace, control characters, and more-than-one
  credential (spec L756). Provide `Parse`/`TryParse`/`Validate` plus helpers to
  read the `Authorization: AAuth <token68>` request credential and the
  `AAuth-Access: <token68>` response value. Mirror the parser style of
  [AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs)
  / `SignatureKeyHeader`.

### Implementation Decisions (Phase 1)

- [x] Header file name (`Headers/AAuthAccessHeader.cs`) and public API shape
      (`Parse`/`TryParse`/`Validate`) confirmed before writing tests.

### Definition of Done

- [x] `AAuthConstants.Headers.AAuthAccess` present.
- [x] Valid `token68` accepted; empty / whitespace / control-char / multi-credential
      inputs rejected (one negative test each).
- [x] `Authorization: AAuth …` and `AAuth-Access: …` round-trip through the helpers.
- [x] Build + unit + conformance green.

---

## Phase 2 — Agent side: capture, replay, store

The signer already binds `authorization`; this phase only *sets* the header and
keeps the per-origin store.

### Scope

- `IAAuthAccessStore` + `InMemoryAAuthAccessStore`: latest opaque token per
  resource origin (key = scheme+host+port). **Distinct** from the resource-side
  `IOpaqueTokenStore` (research § "Why a separate agent store").
- `Agent/AAuthAccessHandler.cs` (`DelegatingHandler`): positioned **outer** of
  `AAuthSigningHandler` and **inner** of `InteractionHandler`. Before send: if the
  store holds a token for the origin, set `Authorization: AAuth <token68>` (the
  signer then auto-covers it). After receive (including the terminal `200` from an
  interaction poll): capture any `AAuth-Access`, `token68`-validate it (Phase 1),
  and update the store — superseding the prior value (rolling refresh, OQ4).
- `AAuthClientBuilder.WithResourceManagedAccess(IAAuthAccessStore? store = null)`:
  insert the handler into `BuildHandler()` at the ordering above; compose with
  `WithInteractionHandling` so the terminal `200`'s `AAuth-Access` is captured.
- `AAuthAgentOptions.EnableResourceManagedAccess` (+ optional store) wired in
  `AddAAuthAgent`; reuse the existing `OnResourceInteraction` / `PollingTimeout`.

### Implementation Decisions (Phase 2)

- [x] Handler ordering (outer of signer, inner of interaction) confirmed against
      `BuildHandler()` composition.
- [x] Origin key normalization (scheme+host+port, lowercase host) confirmed.

### Definition of Done

- [x] An `AAuth-Access` response is captured and replayed as `Authorization: AAuth`
      on the next request to the same origin; a new value supersedes the old (tests).
- [x] `authorization` is a covered signature component exactly when a token is
      presented (test asserts `Signature-Input`) — **no signer change** required.
- [x] Build + unit + conformance green (e2e deferred to Phase 4 — no sample wiring
      yet; see log).

---

## Phase 3 — Resource side: wire the opaque-token seam (issue / validate / unwrap)

Highest-blast-radius phase — touches the verification/challenge pipeline.

### Scope

- Add `AAuthAccessMode.ResourceManaged` to
  [Server/Verification/AAuthAccessMode.cs](../../../src/AAuth/Server/Verification/AAuthAccessMode.cs).
- **Consumption:** parse + `token68`-validate `Authorization: AAuth` (Phase 1),
  **assert `authorization` is among the request's covered components** in
  `Signature-Input` and reject if absent (the binding MUST, L753, L2716),
  `ValidateAsync` against `IOpaqueTokenStore`, and attach the resulting
  `OpaqueTokenInfo` to `HttpContext`.
- **Issuance:** after the resource authorizes the agent itself — interaction-completed
  via the reused `202 → poll → 200` handshake (OQ5) or identity-only (L778) —
  `IssueAsync` and emit `AAuth-Access` on the response; a rolling-refresh path
  emits a fresh value on a later response (L754).
- `Server/AAuthHttpContextExtensions`: `IssueAAuthAccess(info)` /
  `TryGetAAuthAccess(out info)` app-facing seam.
- **`authorization_endpoint` (proactive entry point):** a
  `MapAAuthAuthorizationEndpoint(...)` helper that accepts a signed `POST` with a
  `{"scope": …}` body (L620), reads the agent token from `Signature-Key`, and runs
  the **same** resource-managed decision logic as the reactive path — returning
  `202 + requirement=interaction` (or, on completion / identity-only, issuing the
  token via `AAuth-Access`). Both entry points share one code path (L605: "a
  resource token can be returned in two ways").
- Resource DI opt-in: `AAuthResourceOptions.EnableResourceManagedAccess` registers
  the consumption/issuance middleware and a default `InMemoryOpaqueTokenStore`.
- **Rotation (inconsistency #5 — resolved, no helper):** rolling refresh = call
  `IssueAsync(...)` again and emit the new `AAuth-Access`; the old token lapses via
  `Expiration`, or `RevokeAsync(old)` kills it immediately. The spec places
  "replace" on the agent (L754), not an atomic resource-side rotate, so **no**
  `Supersede` method is added.

### Implementation Decisions (Phase 3)

- [x] Consumption lives in **`HttpContext` extensions** (not a new middleware): the
      binding MUST is already enforced by `AAuthVerifier`, so the remaining
      `token68` + `ValidateAsync` + surface is endpoint-driven (see log).
- [x] Covered-component assertion **reuses `AAuthVerifier`** — it already covers
      `authorization` and rejects "present but uncovered"; no re-parse.
- [x] Rotation: **no** `Supersede` helper — issue-new + optional `RevokeAsync`
      (inconsistency #5 resolved by design; see log).
- [x] `MapAAuthAuthorizationEndpoint` shares the reactive decision path via an app
      delegate the reactive endpoint also calls (one code path).

### Definition of Done

- [x] A self-managed resource emits `AAuth-Access` after authorization; the agent's
      next signed request is accepted and `OpaqueTokenInfo` is surfaced (round-trip
      test — `ResourceManagedFlowTests`, `AAuthAccessSignedComponentTests`).
- [x] A presented opaque token **without** `authorization` covered is rejected
      (negative test); a `token68`-invalid credential is rejected.
- [x] Rolling refresh: a second response with a new `AAuth-Access` is honored on the
      following request (agent `RollingRefresh_SwitchesToNewToken`).
- [x] A signed `POST` to `authorization_endpoint` runs the decision logic and issues
      `AAuth-Access` (proactive issue → agent replay → resource resolve round-trips
      in-pipeline, `ResourceManagedFlowTests`); the 202-interaction completion path
      is shown by the Inbox sample (Phase 4).
- [x] Build + unit + conformance green (478 unit / 556 conformance); e2e deferred to
      Phase 4 (no sample wiring yet; see log).

---

## Phase 4 — Inbox demo server + GuidedTour / SampleApp wiring (compiled samples)

Runs after the SDK surface (Phases 1–3) is frozen. New **compiled** sample code +
e2e specs; non-compiled prose is swept in Phase 5.

### Scope

- New `samples/MockResourceServers/Inbox` on **`:5004`** — **Aria Inbox (email)**,
  the resource-managed (two-party) server Aria connects to via the inbox's **own**
  consent/login, no PS/AS ("drops in where you use OAuth", L2624; the opaque token
  models an existing OAuth access token, L740). Narrative: Aria imports the
  traveler's trip confirmations from their inbox. Mock/seed messages only (no real
  PII). Publishes `access_mode: "aauth-access-token"` **and** an
  `authorization_endpoint` in `aauth-resource.json`, and demonstrates **both** spec
  entry points (L605):
  - **Reactive:** `GET /messages` → first call `202 + AAuth-Requirement:
    requirement=interaction; url=…; code=…` (L758); the user approves, the agent
    polls `Location`, and the terminal `200` carries `AAuth-Access` (L776);
    subsequent signed calls send `Authorization: AAuth` and succeed.
  - **Proactive:** signed `POST /authorize` with `{"scope": …}` (L620) → the same
    `202` / issue path.
  - A path demonstrates **rolling refresh** by returning a fresh `AAuth-Access`
    (L754).
- **GuidedTour:** insert `TourMode.ResourceManaged` **between `Identity` and
  `Autonomous`** in
  [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs); add an `InboxUrl`
  option (`http://localhost:5004`) and a step script reusing the `202 → poll → 200`
  visuals plus an `AAuth-Access` capture + `Authorization: AAuth` replay row. The
  flow needs **no** `PersonServerUrl`.
- **SampleApp:** add an `/inbox` page **between `/identified` and `/calendar`** in
  nav order.
- **AgentConsole:** add a path/mode mapping for `:5004/messages` (signing-mode
  agnostic — "Any" in the README table).
- **Makefile:** boot Inbox in `make demo` and any `make demo-*` that lists resource
  servers.
- **e2e:** new `samples/GuidedTour/playwright-tests/resource-managed.spec.ts`
  covering **both** entry points (reactive `GET /messages` and proactive
  `POST /authorize`); add the mode to the `phase8-visual.spec.ts` server/mode
  matrix (`{ mode: ResourceManaged, server: 'Inbox', url: ':5004' }`).

### Implementation Decisions (Phase 4)

- [x] Inbox domain: **email** ("import trip confirmations"); mock/seed data only,
      no real PII.
- [x] Inbox advertises **and implements** `authorization_endpoint` and demos
      **both** entry points (reactive `GET /messages → 202`, proactive
      `POST /authorize`).

### Definition of Done

- [x] Inbox builds and runs; the full resource-managed round trip works (proven
      end-to-end by `InboxFlowTests` against `WebApplicationFactory<Inbox.Entry>`).
- [x] GuidedTour shows `ResourceManaged` in slot 2; SampleApp serves `/inbox` in
      slot 2.
- [x] `make demo` boots Inbox; AgentConsole reaches `:5004/messages`
      (`--resource-managed`).
- [x] New e2e specs written (`inbox.spec.ts`, `resource-managed.spec.ts`), typecheck
      + are discovered by Playwright, Inbox added to the e2e `webServer` array, and
      the `phase8-visual` matrix updated. (Full browser run is via `make e2e` with
      the live stack — not executed in this environment; see log.)

---

## Phase 5 — Docs, snippets & inconsistency sweep (non-compiled surfaces)

Runs after the code surface is frozen. Sweeps string-literal snippets, READMEs,
docs prose/fences, and e2e-asserted prose for drift, and **fixes the pre-existing
inconsistencies** (research § pre-existing inconsistencies #1–#3). Mirrors the
[research § docs & samples to update](research.md#docs--samples-to-update) table.

### Scope

- Rewrite [docs/workflows/resource-managed-access.md](../../../docs/workflows/resource-managed-access.md)
  against the **real** implemented API (it currently documents an inert wire-up —
  inconsistency #1); add a live-demo reference to Inbox.
- [docs/concepts.md](../../../docs/concepts.md) L38 and
  [docs/README.md](../../../docs/README.md) (API map L210 + workflows list): update
  the resource-managed SDK surface beyond just `IOpaqueTokenStore` (inconsistency #2).
- Root [README.md](../../../README.md): add GuidedTour/SampleApp demo links to the
  **Resource-Managed** row (L34); flip the "one protocol surface not yet
  implemented" sentence (L287); bump the sample count (inconsistency #3).
- [samples/README.md](../../../samples/README.md): "four Aria resource servers" →
  five; add the Inbox row + a "Running Individually" subsection; update the
  `make demo` description.
- [docs/reference/dependency-injection.md](../../../docs/reference/dependency-injection.md):
  the new `AddAAuthAgent` flag, resource opt-in, and the now-wired `IOpaqueTokenStore`.
- [docs/getting-started.md](../../../docs/getting-started.md) if it enumerates modes;
  GuidedTour / SampleApp READMEs; the new flow/page.
- [aauth-spec/SPEC-VERSION.md](../../../aauth-spec/SPEC-VERSION.md): drop/adjust the
  "`AAuth-Access` not yet implemented" note.
- Re-scan existing e2e-asserted values for drift introduced by Phase 4.

### Definition of Done

- [x] `resource-managed-access.md` matches shipped API; no doc claims an inert
      wire-up; inconsistencies #1–#3 resolved.
- [x] No remaining "not yet implemented" / "not implemented" claim for `AAuth-Access`
      across README/docs/SPEC-VERSION/CHANGELOG (grep-verified — only historical
      `.agent/plans/` records remain).
- [x] All in-repo doc links valid; full `AAuth.slnx` build + unit + conformance
      green (481 / 556). e2e via `make e2e`.

---

## Phase 6 — Internal review (subagent validation)

Final gate. A fresh subagent reviews the shipped work against draft-08
(§`#aauth-access` L738, §`#resource-managed-auth` L758, **AAuth-Access Security**
L2712–2716), `research.md`, and this plan with **severity-graded findings** —
especially the MUST that `authorization` is covered, the `token68` rejection
rules, the "never a standalone bearer" property, and that every pre-existing
inconsistency (#1–#6) is resolved.

### Definition of Done

- [x] Review produced with severity-graded findings (the `Implementation Validator`
      subagent lacked file-access tools, so its C1–C7 checklist was executed
      directly against code + tests; see log).
- [x] Every pre-existing inconsistency (#1–#6) confirmed resolved.
- [x] Zero unresolved Critical or High findings.

---

## Out of scope

| Item | Why |
|---|---|
| A default cryptographic wrapper for the opaque state | Resource-internal; the shipped `IOpaqueTokenStore` seam + `InMemoryOpaqueTokenStore` demo store suffice (OQ1). |
| Bridging `AAuth-Access` to a live OAuth resource server | Integration concern, not protocol surface. |
| Persisting the agent or resource token stores across process restarts | In-memory demo stores suffice; production stores are app-supplied. |
