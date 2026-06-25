# Implementation Plan — AAuth-Access opaque-token flow

Companion to [`research.md`](research.md). Adds the draft-08 **`AAuth-Access`**
opaque-token flow (the `aauth-access-token` access mode) to `src/AAuth/`,
`samples/`, `docs/`, and `tests/`, bringing the SDK to parity with
[`aauth-spec/v08/`](../../../aauth-spec/v08/) §`#aauth-access` (L738) and
§`#resource-managed-auth` (L758). Decisions and deviations are recorded in
`implementation-log.md` (added when work begins).

> Status: **Not started — plan only.** This initiative was scoped out of the
> [draft-08 migration](../2026-06-25-aauth-v08-spec-migration/implementation-plan.md)
> (its Phase 3 recorded the `AAuth-Access` `token68` validation as N/A because no
> consumption/production path existed). Nothing here is implemented yet. Verify
> each spec line reference against [`aauth-spec/v08/`](../../../aauth-spec/v08/)
> before editing a file — see the verification note in `research.md`.

## Guiding principles (apply to every phase)

- **Spec accuracy over compatibility.** Match draft-08 exactly. This is a
  spec-accurate alpha SDK with no back-compat guarantee; breaking changes are
  acceptable when they buy spec accuracy. Single coordinated cutover (the SDK
  signs *and* verifies) — no dual-format shims.
- **Reuse the deferred/interaction machinery.** The resource-managed `202 →
  poll → 200` handshake reuses `DeferredPoller` / `Interaction`; add only the
  trailing `AAuth-Access` capture + replay. Confirm before rebuilding.
- **Bind the token to the signature.** The opaque token is never a standalone
  bearer credential — `authorization` MUST be a covered HTTP-signature component
  whenever an `AAuth-Access` token is presented (spec L753, L2712).
- **Per-phase e2e gate.** Each code phase ends by running the e2e (Playwright
  guided-tour + sample-app) suites against a fresh full-stack boot (`make e2e`;
  boot the whole backend set together). A phase that changes an e2e-asserted value
  updates that spec in the same phase.

## Summary of the change

| Area | From (current) | To (draft-08) | Phase |
|---|---|---|---|
| `token68` grammar | none | parse/validate (reject empty / whitespace / control / multi) | 1 |
| Agent token replay | none | capture `AAuth-Access`, replay `Authorization: AAuth`, rolling refresh | 2 |
| Signature binding | covers `@method @authority @path` + signature-key | also cover `authorization` when a token is present | 2 |
| Resource issuance | none | emit `AAuth-Access` after self-managed authorization | 3 |
| Resource consumption | none | validate `Authorization: AAuth` `token68` + covered-component check; unwrap | 3 |
| Samples / docs | no opaque-token demo | resource-managed-access sample + docs | 4 |

---

## Phase 0 — Decision gate

Resolve `research.md` OQ1–OQ5 before code. No code in this phase; record each
ruling in `implementation-log.md` and tick the matching box.

### Implementation Decisions (Phase 0)

- [ ] **OQ1** Opaque-state wrapping seam (default codec vs app seam only).
- [ ] **OQ2** Per-origin replay store ownership (sibling handler + injectable store).
- [ ] **OQ3** `authorization` covered-component toggle (auto when token present).
- [ ] **OQ4** Rolling-refresh race rule (last-writer-wins, no serialization).
- [ ] **OQ5** Confirm `DeferredPoller`/`Interaction` reuse for the `202→200` handshake.

### Definition of Done

- [ ] Each OQ has a recorded ruling (or `default X, revert if you disagree`) in
      `implementation-log.md`.

---

## Phase 1 — `token68` grammar utility

Lowest-risk, pure function (no flow yet).

### Scope

- Add a `token68` parser/validator (e.g. `Headers/AAuthAccessToken.cs`): accept a
  single RFC 9110 §11.2 `token68`; reject empty, embedded whitespace, control
  characters, and multiple credentials (spec L756).
- Helpers to parse the `Authorization: AAuth <token68>` request header and the
  `AAuth-Access` response header into a validated value.

### Definition of Done

- [ ] Valid `token68` accepted; empty / whitespace / control-char / multi-credential
      inputs rejected (negative tests for each).
- [ ] Build + unit + conformance green.

---

## Phase 2 — Agent side: capture, replay, and signature binding

### Scope

- A sibling `DelegatingHandler` (near `AAuthSigningHandler`) that, per resource
  origin, captures the latest `AAuth-Access` response value, stores it via an
  injectable store (OQ2), and replays it as `Authorization: AAuth …` on the next
  request, switching to any new value (rolling refresh, OQ4).
- Add `authorization` to the HTTP Message Signature covered components when a
  stored token is present for the target origin (OQ3), so the sent header is
  covered (spec L753).
- Wire into `AAuthClientBuilder` as an opt-in.

### Definition of Done

- [ ] An `AAuth-Access` response is captured and replayed as `Authorization: AAuth`
      on the next request to the same origin; a new value supersedes the old (tests).
- [ ] `authorization` is a covered signature component exactly when a token is
      presented (test asserts `Signature-Input`).
- [ ] Build + unit + conformance green; e2e green.

---

## Phase 3 — Resource side: issue, validate, and unwrap

### Scope

- Resource issuance: after the resource authorizes the agent itself
  (interaction-completed via the reused `202→poll→200` handshake, or identity-only),
  emit an `AAuth-Access` header wrapping app-supplied internal state (OQ1), wired
  into the verification/challenge pipeline.
- Resource consumption: parse + `token68`-validate `Authorization: AAuth`
  (Phase 1), confirm `authorization` is in the request's covered components, unwrap
  the internal state, and surface it on the verification result.
- Confirm the `202 + requirement=interaction → 200 + AAuth-Access` handshake reuses
  the deferred/interaction machinery (OQ5).

### Definition of Done

- [ ] A self-managed resource emits `AAuth-Access` after authorization; the agent's
      next signed request is accepted and the wrapped state is surfaced (round-trip test).
- [ ] A presented opaque token without `authorization` covered is rejected
      (negative test); a `token68`-invalid credential is rejected.
- [ ] Build + unit + conformance green; e2e green.

---

## Phase 4 — Samples, snippets, and docs

Runs after the API surface is frozen.

### Scope

- A runnable resource-managed-access sample (a resource that issues `AAuth-Access`
  + an agent that replays it), reconciled against interop profile Surface 3
  (resource-managed access) in
  [interop-demo-profile.md](../../../aauth-spec/v08/interop-demo-profile.md).
- Docs: a `docs/workflows/resource-managed-access.md` (or update the existing
  resource-managed workflow) covering the handshake, the `authorization` binding,
  and rolling refresh; update the access-mode reference.

### Definition of Done

- [ ] Sample builds and runs against a fresh full-stack boot; e2e green.
- [ ] Docs cover the flow, the signature binding, and rolling refresh; links valid.
- [ ] Full `AAuth.slnx` build + unit + conformance + e2e green.

---

## Phase 5 — Internal review (subagent validation)

Final gate. A fresh subagent reviews the shipped work against draft-08
(§`#aauth-access` L738, §`#resource-managed-auth` L758, **AAuth-Access Security**
L2712), `research.md`, and this plan with **severity-graded findings** —
especially the MUST that `authorization` is covered, the `token68` rejection
rules, and the "never a standalone bearer" property.

### Definition of Done

- [ ] Review subagent report produced with severity-graded findings.
- [ ] Zero unresolved Critical or High findings.

---

## Out of scope

| Item | Why |
|---|---|
| A default cryptographic wrapper for the opaque state | Resource-internal; ship a seam + demo store unless OQ1 rules otherwise. |
| Bridging `AAuth-Access` to a live OAuth resource server | Integration concern, not protocol surface. |
| Persisting the per-origin token store across process restarts | In-memory demo store suffices; production stores are app-supplied. |
