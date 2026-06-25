# Implementation Plan — AAuth SDK migration to protocol draft-08

Companion to [`research.md`](research.md). Brings `src/AAuth/`, `samples/`,
`docs/`, and `tests/` into conformance with **AAuth protocol draft-08**
([`aauth-spec/v08/`](../../../aauth-spec/v08/)) from the current **draft-02**
baseline. Decisions and deviations are recorded in
[`implementation-log.md`](implementation-log.md) for end-of-run review.

> Status: **In progress.** Phases are ordered by risk and dependency: the cheap,
> isolated changes land first; the large `act`/verification rework (the spine)
> lands mid-stream; the security work trails. Each code phase ends by running the
> **e2e (Playwright guided-tour + sample-app) suites** against a fresh full-stack
> boot, so live-workflow regressions surface immediately. A dedicated
> samples/snippets/docs sweep (Phase 8) runs after the API surface is frozen; the
> `AAuth-Access` opaque-token flow is spun off as its own research + plan
> initiative (Phase 9 — no implementation here); a subagent internal-review gate
> closes the work (Phase 10). Nothing here is committed until the owner reviews.
> Verify each spec line reference against
> [`aauth-spec/v08/`](../../../aauth-spec/v08/) before editing a file — see the
> verification note at the end of `research.md`.

## Guiding principles (apply to every phase)

- **Spec accuracy over compatibility.** Match draft-08 exactly. The repo is a
  spec-accurate alpha SDK with no back-compat guarantee (2026-06-09 precedent);
  breaking renames/removals (`act.sub`→`act.agent`, `client_name`→`name`) are
  acceptable when they buy spec accuracy (pending Q1).
- **Verify already-satisfied work before rebuilding.** Call-chaining routing, the
  `aud == iss` binding, the `Signature-Error` header, JWKS same-`kid` refresh, and
  `jti` replay detection already exist. Confirm against draft-08, then add only the
  missing behavior — do not re-implement.
- **One coordinated cutover for `act`.** The SDK signs *and* verifies, so the
  `act.sub`→`act.agent` change flips both sides in the same phase; no dual-format
  shim.
- **Delete dead code; keep diffs spec-shaped.** Prefer renames over additive
  aliases unless an open question explicitly calls for a fallback.
- **Two-tier samples/docs handling.** Each code phase updates whatever is needed
  to keep the full `AAuth.slnx` build + unit + conformance green — including
  *compiled* sample code that references a renamed/changed API (e.g. a renamed
  metadata property breaks sample compilation and must be fixed in-phase). The
  *non-compiled* surfaces drift silently because they never break the build:
  string-literal snippets in [samples/GuidedTour/CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs),
  illustrative `<pre><code>` blocks in SampleApp Razor pages, READMEs, and `docs/`
  prose and embedded code fences. These are swept comprehensively in **Phase 8**
  once the API surface is frozen, so the analysis is done against final shapes
  rather than re-done after every phase. e2e/Playwright spec assertions are the
  exception (see the e2e gate below): they are an executable per-phase gate, so a
  spec broken by a phase's change is fixed in that phase, not deferred.
- **Per-phase e2e gate.** Every code phase ends by running the e2e (Playwright
  guided-tour + sample-app) suites against a fresh full-stack boot (`make e2e`;
  honour the harness rule — boot the whole backend set together, never restart one
  resource server against a live PS). When a phase changes a value an e2e spec
  asserts (e.g. `act.sub`→`act.agent`, a scope, a path, a metadata field), that
  spec is updated **in the same phase** so the gate stays green. Phases 1–4 are
  validated against e2e retroactively before Phase 5 proceeds.

## Summary of the change

| Area | From (draft-02 / current) | To (draft-08) | Phase |
|---|---|---|---|
| HTTP Signature Keys reference | draft-04 citations | draft-05 citations + SSRF/egress docs | 1 |
| Metadata display name | `client_name` | `name` (all roles) | 2 |
| Metadata docs | no `documentation_uri` | `documentation_uri` (+ `logo_dark_uri`/`tos_uri`/`policy_uri`) on all four | 2 |
| Agent keying material | any signature-key scheme | `scheme=jwt` only | 3 |
| Mission reference | loose `approver`/`s256` | server-id `approver`; unpadded base64url `s256` | 3 |
| `AAuth-Access` / headers | minimal validation | `token68` + ignore-unknown forward-compat | 3 |
| Auth-token `act` | always present; `act.sub`; self-reference | OPTIONAL; `act.agent`; upstream delegator | 4 |
| Auth-token verification | single pass | JWT-trust + request-context split; ordered `cnf.jwk` | 4 |
| Four-party call chaining | mission optional | PS MUST require a mission | 5 |
| Interaction callback | none | `?error=` wire format + PS→polling mapping | 6 |
| Interaction code | "only secret" framing | correlation identifier (doc framing) | 6 |
| Samples / snippets / docs | scattered, drift silently | swept after code freeze (analysis + update) | 8 |
| PS approval endpoint | unauthenticated | MUST authenticate (loopback exempt) | 7 |
| JWKS refresh | refresh on unknown `kid` | also refresh once on verify failure | 7 |
| Delegation docs/terminology | top-level sections; `act.sub` | `# Agent Delegation` nesting; `act.agent` | 8 |

---

## Phase 0 — Decision gate

Resolve `research.md` Q1–Q9 before code. No code in this phase; record each
ruling (and its rationale) in [`implementation-log.md`](implementation-log.md)
and tick the matching box below.

### Implementation Decisions (Phase 0)

- [x] **Q1** No-back-compat posture confirmed for draft-08 (clean renames, single
      cutover).
- [x] **Q2** `ResourceMetadata` `name`-only vs `name`-with-`client_name`-fallback
      decided.
- [x] **Q3** PS-vs-AS determination strategy for the four-party mission gate
      chosen (metadata probe / configured AS list / heuristic).
- [x] **Q4** Owner of interaction `?error=` callback parsing decided (agent /
      PS / both), after auditing the PS resource-initiated flow.
- [x] **Q5** Four-party "mission required" error code chosen (default
      `invalid_request` + description).
- [x] **Q6** Freshness/replay: confirm existing `jti`/`created` machinery suffices
      or the spec cache key is needed.
- [x] **Q7** Egress-admission/SSRF: deployment-level + docs vs SDK hook.
- [x] **Q8** Approval-endpoint auth shape (app-supplied verifier + loopback
      exemption).
- [x] **Q9** Sub-agent (S5) interop sample: build vs defer.

### Definition of Done

- [x] Each of Q1–Q9 has a recorded ruling (or an explicit "default X, revert if
      you disagree") in [`implementation-log.md`](implementation-log.md).

---

## Phase 1 — HTTP Signature Keys draft-05 reference sweep

Lowest-risk, no behavioral code change (change set 6).

### Scope

- Update `draft-hardt-httpbis-signature-key-04` / `draft-04` citations to
  `-05` / `draft-05` in code comments and docs (e.g.
  [HttpSig/DefaultSignatureKeyResolver.cs](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs),
  [docs/workflows/bootstrap-enrollment.md](../../../docs/workflows/bootstrap-enrollment.md)).
- Add an SSRF/egress-admission deployment checklist (draft-05 §6.3) to the server
  docs (e.g. [docs/server/verification-middleware.md](../../../docs/server/verification-middleware.md)).
- Optional: a regression test asserting JWKS silent re-keying (same `kid`, new
  material) refreshes once and succeeds.

### Definition of Done

- [x] No `signature-key-04` / `draft-04` residue in `src/` or `docs/` (grep clean).
- [x] SSRF/egress checklist present in server docs.
- [x] Build + unit + conformance green.

---

## Phase 2 — Metadata documents (`name` rename + `documentation_uri`)

Isolated, low risk (change set 4).

### Scope

- Client: [Discovery/ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs)
  — rename `ClientName` → `Name` (parse `name`; per Q2, optional `client_name`
  fallback on `ResourceMetadata`); add `DocumentationUri`, `LogoDarkUri`,
  `TosUri`, `PolicyUri`.
- Server options: rename `ClientName` → `Name` and add the new optional fields on
  [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs),
  the resource options in
  [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs),
  and add `Name` + the new fields to
  [AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs)
  and [AAuthAccessServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs).
- Server builders: emit `name` (not `client_name`) and conditional
  `documentation_uri` / `logo_dark_uri` / `tos_uri` / `policy_uri` across all four
  builders in `WellKnownEndpoints`.
- Samples: update any DI configuration setting `ClientName`.
- Docs: note the RFC 9728 divergences and the unprefixed common-field names.

### Definition of Done

- [x] All four well-known documents emit `name` (no `client_name`) and accept
      `documentation_uri`.
- [x] Client parses `name` and `documentation_uri`; round-trip tests updated.
- [x] No `ClientName`/`client_name` residue in `src/` (grep clean, modulo any Q2
      fallback).
- [x] Build + unit + conformance green.

---

## Phase 3 — Validation tightening (`scheme=jwt`, mission syntax, header grammars)

Independent validation hardening (change set 5b/5c/5d).

### Scope

- **`scheme=jwt` restriction (5c):** after parsing an agent token's
  `Signature-Key`, require `scheme=jwt` (dwk `aauth-agent.json`); reject `hwk` /
  `jkt-jwt` / `jwks_uri` for agent keying material —
  [HttpSig/SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs) /
  [HttpSig/AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs) /
  [Tokens/TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs).
- **Mission `approver`/`s256` syntax (5b):** validate `approver` via
  [Identifiers/ServerId.cs](../../../src/AAuth/Identifiers/ServerId.cs) and `s256`
  as unpadded base64url of 32 bytes in [Agent/Mission.cs](../../../src/AAuth/Agent/Mission.cs)
  / [Agent/MissionHeaderHandler.cs](../../../src/AAuth/Agent/MissionHeaderHandler.cs).
- **Header grammars (5d):** reject empty / embedded-whitespace / multi-credential
  `AAuth-Access` (`token68`); document ignore-unknown behavior for
  [Headers/AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs)
  parameters and [Agent/AAuthCapabilitiesHeader.cs](../../../src/AAuth/Agent/AAuthCapabilitiesHeader.cs)
  values.

### Definition of Done

- [x] Agent tokens presented with a non-`jwt` scheme are rejected (negative test).
- [x] Invalid `approver` (non-https / has port/path) and padded/short `s256` are
      rejected (negative tests).
- [x] Unknown `AAuth-Requirement` params and `AAuth-Capabilities` values are
      ignored, not rejected (already satisfied). **`AAuth-Access` token68 is N/A:**
      the SDK has no `Authorization: AAuth` consumption path to validate — see log.
- [x] Build + unit + conformance green.

---

## Phase 4 — Auth-token `act` rework + verification split (the spine)

The largest, highest-blast-radius change (change set 1 + 5f). Single coordinated
cutover.

### Scope

- **`act.sub` → `act.agent`, `act` OPTIONAL:**
  [Tokens/ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs),
  [Tokens/ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs),
  [Tokens/AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs)
  (emit `act` only when delegated; node uses `agent`; omit for direct auth),
  [Tokens/UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs)
  (`act` optional; check `act.agent` is the upstream agent).
- **Verification split (5f):** restructure
  [Tokens/TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs) into
  JWT-trust (typ/dwk/sig/exp/iat/iss) and request-context binding
  (aud/agent/`cnf.jwk`/`act`/sub-or-scope) with the ordered `cnf.jwk` failures
  (structurally-incomplete before decode; invalid-key-material on parse failure;
  then PoP match). Reflect in
  [Server/Verification/AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs)
  and [Server/Verification/AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs).
- Update PS/AS auth-token issuance to set `act.agent` and nest the upstream chain;
  sub-agent issuance sets `act.agent` = parent.
- Update all `act.sub`/always-present-`act` assertions in conformance + e2e tests.

### Definition of Done

- [x] Direct-authorization auth tokens omit `act`; chained/sub-agent tokens carry
      `act.agent` (with nesting); no `act.sub` or self-referential `act` remains in
      `src/` (grep clean).
- [x] Verification tolerates absent `act`, checks `act.agent` when present, and
      enforces the ordered `cnf.jwk` failure classification (negative tests for
      each ordering branch).
- [x] Conformance tests updated to `act.agent`/optional-`act` and green.
      (Playwright/e2e act assertions are part of the Phase 8 sweep.)
- [x] Build + unit + conformance green.

---

## Phase 5 — Four-party call-chaining PS mission gate

Small, isolated rule on top of already-compliant routing (change set 2).

### Scope

- In the PS token endpoint
  ([Person/AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)),
  when an `upstream_token` is present, the request has no mission, and the upstream
  `iss` resolves to an AS (per Q3), reject with the Q5 error.
- No change to [CallChainingRouter.cs](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs)
  or [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs)
  for the binding/routing rules (already compliant).

### Definition of Done

- [x] Four-party upstream chain without a mission is rejected; three-party upstream
      without a mission is still allowed (tests for both).
- [x] Existing routing/`aud==iss` tests remain green.
- [x] Build + unit + conformance green; e2e (guided-tour + sample-app) green.

---

## Phase 6 — Interaction callback errors + interaction-code framing

Change set 3.

### Scope

- Add the five callback error constants and the callback→polling mapping
  (`access_denied`→`denied`, `user_abandoned`→`abandoned`,
  `interaction_expired`→`expired`, `server_error`/`temporarily_unavailable`→
  `server_error`) alongside [Errors/PollingError.cs](../../../src/AAuth/Errors/PollingError.cs).
- Parse `?error=` on interaction callbacks and surface (never treat as
  completable) on the owning side per Q4 —
  [Agent/DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs) /
  [Agent/DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs) and/or
  [Person/AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs).
- Reframe the [Headers/InteractionCode.cs](../../../src/AAuth/Headers/InteractionCode.cs)
  doc comment to "correlation identifier, not an authorization credential" (no
  behavioral change); refresh the Crockford citation in docs.

### Definition of Done

- [x] Each `?error=` value maps to the correct polling error; unknown values
      default to `server_error`; missing `error` is treated as a non-error redirect
      (tests).
- [x] Interaction-code framing updated; pure-function code behavior unchanged
      (existing tests green).
- [x] Build + unit + conformance green; e2e (guided-tour + sample-app) green.

---

## Phase 7 — PS approval endpoint authentication + JWKS/replay hardening

Security cluster (change set 5a/5e/5g).

### Scope

- **PS approval endpoint auth (5a):** add an authentication guard before
  consent/denial in [Person/AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)
  with a loopback-only exemption and an app-supplied verifier (per Q8);
  default-deny when externally reachable and unauthenticated.
- **JWKS refresh-on-failure (5e):** optionally extend
  [Discovery/JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs) to refresh
  once when a cached `kid` fails verification (silent re-keying), within the
  once-per-minute floor.
- **Freshness/replay (5g):** confirm
  [HttpSig/AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs) +
  [Server/InMemoryJtiStore.cs](../../../src/AAuth/Server/InMemoryJtiStore.cs)
  satisfy the subsection (per Q6); align the optional replay cache key to
  `(thumbprint, created, @method, @authority, @path)` only if a resource opts in;
  otherwise docs-only.

### Definition of Done

- [x] Externally-reachable PS approval endpoint rejects unauthenticated decisions;
      loopback bypass works (tests for both).
- [x] JWKS silent re-keying handled (test) or explicitly deferred per Q6/Q7.
- [x] Freshness/replay conformance confirmed; any cache-key alignment tested.
- [x] Build + unit + conformance green; e2e (guided-tour + sample-app) green.

---

## Phase 8 — Samples, code snippets, and docs: post-code analysis & update

Runs **after Phases 1–7 are code-complete and the API surface is frozen**.
Earlier phases keep the solution compiling and tests green; this phase is the
holistic correctness/consistency sweep of every *non-compiled* surface plus
runtime/e2e behavior. It folds in the change-set-7 delegation terminology sweep
and interop-profile reconciliation. Done as two stages — analyze, then update —
so the inventory is built once against final API shapes.

### Stage 1 — Analysis (read-only impact inventory)

Dispatch parallel read-only subagents (one per surface category) to produce a
single impact inventory keyed to the concrete Phase 1–7 deltas: `client_name`→
`name`, new `documentation_uri`, `scheme=jwt` restriction, mission
`approver`/`s256` syntax, `act.sub`→`act.agent` + optional `act`, the four-party
PS mission gate, interaction `?error=` callbacks, and PS approval-endpoint auth.
Categories to inventory:

1. **Runnable sample apps** — [AgentConsole](../../../samples/AgentConsole/),
   [Concierge](../../../samples/Concierge/), [GuidedTour](../../../samples/GuidedTour/),
   [LiveWhoAmITest](../../../samples/LiveWhoAmITest/), [MissionAgent](../../../samples/MissionAgent/),
   [MockAccessServer](../../../samples/MockAccessServer/), [MockAgentProvider](../../../samples/MockAgentProvider/),
   [MockPersonServer](../../../samples/MockPersonServer/), [MockResourceServers](../../../samples/MockResourceServers/),
   [SampleApp](../../../samples/SampleApp/) — for behavioral drift that compiles but
   is now wrong (e.g. servers emitting `client_name`, agents building
   self-referential `act`, a four-party path with no mission, metadata missing
   `documentation_uri`).
2. **GuidedTour educational snippets** — the string constants in
   [samples/GuidedTour/CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs)
   and their `StepRecord`/`TourSession` wiring (string literals, never compiled —
   they drift silently).
3. **SampleApp illustrative snippets** — `<pre><code>` blocks in
   `samples/SampleApp/Components/Pages/*.razor`.
4. **READMEs** — top-level [README.md](../../../README.md) and each
   `samples/*/README.md`.
5. **Docs** — prose terminology and embedded code fences across
   [docs/](../../../docs/) (e.g. [call-chaining.md](../../../docs/workflows/call-chaining.md),
   [verification-middleware.md](../../../docs/server/verification-middleware.md),
   [glossary.md](../../../docs/glossary.md),
   [interaction-chaining.md](../../../docs/advanced/interaction-chaining.md),
   [token-issuance.md](../../../docs/server/token-issuance.md), the signing-modes
   pages, and the metadata/configuration reference).
6. **e2e / Playwright** — `samples/*/playwright-tests/*.spec.ts` and
   [tests/e2e/](../../../tests/e2e/) assertions (e.g. `act.sub`, `client_name`,
   scope/path expectations).
7. **Interop demo profile** — reconcile sample coverage against S1–S5 in
   [interop-demo-profile.md](../../../aauth-spec/v08/interop-demo-profile.md);
   record the S5 (sub-agent) gap and the Q9 decision.

Output: an inventory table (surface | file | what changed | required edit),
surfaced for owner review **before** any edits.

### Stage 2 — Update

Apply the inventory edits by category. Run each affected sample against a fresh
full-stack boot (per the repo e2e harness rule — boot the whole backend set
together, never restart one resource server against a live PS) and run the full
Playwright/e2e suites. Compile-check doc/snippet code against the real SDK where
feasible rather than eyeballing.

### Definition of Done

- [x] Impact inventory produced and reviewed; no surface left "unknown".
- [x] `CodeSnippets.cs` constants and SampleApp `<pre><code>` snippets reflect the
      draft-08 API (no `client_name`, no `act.sub`, no self-referential `act`,
      etc.).
- [x] Top-level + per-sample READMEs and `docs/` prose/code fences updated; no
      `act.sub`, `client_name`, or stale top-level-section references remain in
      `docs/`, `samples/`, or `README.md` (grep clean).
- [x] Every runnable sample builds and runs against a fresh full-stack boot;
      Playwright/e2e suites green.
- [x] Interop profile S1–S5 coverage documented; S5 gap resolved per Q9.
- [x] Full `AAuth.slnx` build + unit + conformance + e2e green; doc links valid.

---

## Phase 9 — AAuth-Access opaque-token flow: research & plan (spin-off)

Runs after the migration's code surface is frozen. **Deliverable: a new
research + plan initiative only — do NOT implement the flow here.** Phase 3
recorded that the SDK has no `Authorization: AAuth` / `AAuth-Access` opaque-token
consumption path, so the draft-08 `token68` validation (reject empty / embedded
whitespace / control chars / multiple credentials) has nothing to attach to. This
phase scopes that future work as its own initiative under `.agent/plans/`,
following [`plan-workflow.instructions.md`](../../../.github/instructions/plan-workflow.instructions.md).

### Scope

- Create `.agent/plans/<YYYY-MM-DD>-aauth-access-token-flow/` with:
  - `research.md` — the draft-08 `AAuth-Access` response header and
    `Authorization: AAuth` request flow (`#aauth-access`, L738–756): the `token68`
    grammar and rejection rules, the resource-managed-authorization handshake
    (`202` + interaction → `200` + `AAuth-Access`), rolling refresh, the MUST to
    cover `authorization` in the HTTP signature, and an inventory of where the SDK
    would consume/produce it (agent client, resource middleware/challenge). Cite
    the spec by line number per the authoring rules.
  - `implementation-plan.md` — a phased plan to add the opaque-token flow
    (agent-side: store/replay the `AAuth-Access` value, cover `authorization`;
    resource-side: issue + validate `token68`, wire it to the challenge pipeline),
    with a Phase 0 decision gate and DoD checkboxes.
- Do **not** write any `src/` code for the flow in this migration.

### Definition of Done

- [x] New `.agent/plans/<date>-aauth-access-token-flow/{research.md,implementation-plan.md}`
      created, spec-cited, and self-consistent.
- [x] This migration's Phase 3 `AAuth-Access` N/A deviation links to the new
      initiative.
- [x] No `src/` changes for the flow (the migration stays scoped).

---

## Phase 10 — Internal review (subagent validation)

Final gate. Runs **after Phases 1–9 are complete**. A fresh subagent reviews the
shipped work against the spec and this plan with **severity-graded findings**, so
conformance and security issues are caught before the work is considered done.
Independent of the implementer's own checks — the reviewer starts cold from the
diff plus the source documents.

### Scope

- Dispatch a review subagent (e.g. **Implementation Validator** for
  spec/design conformance, then **PR Review** for code quality + OWASP security)
  with the full change diff and three reference documents: draft-08
  ([`aauth-spec/v08/`](../../../aauth-spec/v08/)), [`research.md`](research.md),
  and this plan. Each finding is graded **Critical / High / Medium / Low** with a
  file:line and a remediation.
- Targeted review checklist (the highest-risk deltas from `research.md`):
  - **`act`**: direct-auth tokens omit `act`; chained/sub-agent tokens use
    `act.agent` (upstream delegator, never self); nesting correct; no `act.sub`
    residue.
  - **Verification split**: JWT-trust vs request-context binding enforced; ordered
    `cnf.jwk` failures (structurally-incomplete → invalid-key → PoP mismatch).
  - **Call chaining**: four-party PS mission gate enforced; routing/`aud==iss`
    unchanged and still correct.
  - **Tightening**: `scheme=jwt` agent-key restriction; mission `approver`/`s256`
    syntax; `AAuth-Access` `token68`.
  - **Metadata**: `name` (no `client_name`); `documentation_uri` on all four docs.
  - **Interactions**: `?error=` parsing + PS→polling mapping; never treat an error
    callback as completable.
  - **Security (OWASP)**: PS approval-endpoint auth (default-deny when externally
    reachable; loopback exemption sound); no SSRF regression on metadata/JWKS
    fetch; no secret leakage via the interaction code (correlation-only).
  - **No-back-compat hygiene**: no stale draft-02 wire values, identifiers, or doc
    wording left behind (grep clean).
- Triage the report: fix every **Critical/High** finding (re-run the affected
  phase's tests); record **Medium/Low** with a ruling (fix now, defer, or move to
  Out of Scope). Re-review if Critical/High fixes were substantial.

### Definition of Done

- [x] Review subagent report produced with severity-graded findings against
      draft-08, `research.md`, and this plan.
- [x] Zero unresolved **Critical** or **High** findings.
- [ ] Every **Medium/Low** finding has a recorded ruling (fixed / deferred /
      out-of-scope).
- [ ] Final full `AAuth.slnx` build + unit + conformance + e2e green after any
      review-driven fixes.

---

## Out of scope (unless promoted by a decision above)

| Item | Reason | Revisit when |
|---|---|---|
| First-class SSRF/egress-admission API in the SDK | draft-05 §6.3 is deployment-level (HttpClient + network policy) | Q7 says otherwise, or a concrete SSRF gap is found |
| Mandatory replay cache for resource tokens | Spec explicitly does **not** require it | A resource opts into state-changing replay protection |
| Runnable sub-agent (S5) interop sample/e2e | SDK logic exists; no live sample today | Q9 says build, or interop testing needs it |
| RFC 9728 alignment beyond the documented divergences | Spec intentionally diverges (`issuer`, unprefixed names) | Upstream changes the divergence stance |
| Nonce-based replay defense | "This profile defines no nonce mechanism" | Spec adds a nonce mechanism |
