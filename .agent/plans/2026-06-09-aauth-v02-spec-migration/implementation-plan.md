# Implementation Plan — AAuth SDK migration to protocol draft-02

Companion to [`research.md`](research.md). Brings `src/AAuth/`, `samples/`,
`docs/`, and `tests/` into conformance with **AAuth protocol draft-02**
([`aauth-spec/v02/`](../../../aauth-spec/v02/)). Decisions and deviations are
recorded in [`implementation-log.md`](implementation-log.md) for end-of-run
review.

> Status: **Phase 0 not started.** Phases are ordered by risk and dependency:
> the two cheap conformance fixes (one a security fix) land first, the large
> net-new sub-agents feature lands mid-stream once supporting seams exist, and
> docs-only work trails. Nothing here is committed until the owner reviews.

## Guiding principles (apply to every phase)

- **Spec accuracy over compatibility.** Match draft-02 exactly. The 2026-06-09
  `jkt-jwt` work established the owner principle *"this repo is a spec-accurate
  alpha SDK; no back-compat."* That carries here (pending Q9 confirmation):
  breaking renames/removals are acceptable when they buy spec accuracy.
- **Verify forward-looking work before rebuilding.** `prompt`/`capabilities`
  (client side) and the `jkt-jwt` restriction already shipped. Confirm against
  published v02, then wire the missing server side — do not re-implement.
- **Published spec beats planning notes.** Where
  [`upcoming-changes-02.md`](../../../aauth-spec/v01/upcoming-changes-02.md)
  disagrees with published v02 (the `user_unreachable` status), published v02
  wins.
- **Delete dead code; one coordinated cutover.** The SDK signs *and* verifies, so
  it stays internally consistent without dual-format shims.

## Summary of the change

| Area | From (draft-01 / current) | To (draft-02) | Phase |
|---|---|---|---|
| Terminal "no channel" error | `user_unreachable` emitted **400** | **403** | 1 |
| Metadata fetch | no issuer verification | reject if `issuer` ≠ fetch URL | 1 |
| Resource metadata | no `access_mode`; `jwks_uri` required | `access_mode` field; `jwks_uri` conditional | 2 |
| Identity challenge | only `auth-token` | add `requirement=agent-token` (401) | 2 |
| Interaction errors | none for relay-unavailable | `interaction_unavailable` (424), non-terminal | 3 |
| Interaction request | no `max_wait`/`status` | `max_wait` param + `status:"interacting"` | 3 |
| Interaction code | opaque pass-through | Crockford base32 format + validation | 3 |
| Sub-agents | none | `parent_agent`, `subagent_token`, single-level depth, `act` nesting | 4 |
| PS token params (server) | ignored | read + flow `prompt`/`capabilities` | 5 |
| Metadata `description` | none | optional Markdown on all four docs | 6 |
| Signing-mode docs | imply hwk/jkt-jwt are full modes | clarify minimum-credential + non-repudiation | 7 |

---

## Phase 0 — Decision gate

Resolve the open questions from `research.md` (Q1–Q9) before code. No code in
this phase; record answers in `implementation-log.md`.

### Implementation Decisions (Phase 0)

- [x] **Q1** `user_unreachable` = 403 confirmed as the target (supersedes 400).
- [x] **Q2** Metadata issuer-mismatch exception type chosen — new `AAuthMetadataException`.
- [x] **Q3** `AAuthAccessMode` additive (`AgentTokenRequired`); wire `access_mode` modeled separately.
- [x] **Q4** Interaction-code generator/validator owned by the SDK (`InteractionCode` utility).
- [x] **Q5** `interaction_unavailable` (424) modeled as a structured outcome, not an exception.
- [x] **Q6** Markdown sanitization is the UI/consumer responsibility; no SDK sanitizer dependency.
- [x] **Q7** `prompt`/`capabilities` tolerant pass-through; refresh = replace; `AdditionalParameters` bag for `provider_hint`.
- [x] **Q8** Sub-agent failures reuse `invalid_request` with distinct descriptions.
- [x] **Q9** No-back-compat posture confirmed for this migration.

### Definition of Done

- [x] Each of Q1–Q9 has a recorded ruling (or an explicit "default X, revert if
      you disagree") in `implementation-log.md`.


---

## Phase 1 — Critical conformance fixes (wire mismatch + security)

Two small, high-value changes. Land first; everything else builds on a correct
baseline. **Status: complete (2026-06-09).**

### 1a. `user_unreachable` 400 → 403

- `src/AAuth/Agent/DeferredExchange.cs` L191 — `statusCode: 400` → `403`.
- `src/AAuth/Errors/TokenError.cs` — fix the `UserUnreachable` doc comment.
- `docs/advanced/error-handling.md` — update the documented status.
- `tests/AAuth.Conformance/Errors/TokenErrorTests.cs`,
  `tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs` (theory `InlineData` 400→403),
  `tests/AAuth.Tests/Agent/InteractionChainingTests.cs` — add an explicit
  `StatusCode == 403` assertion.

### 1b. Metadata issuer host-binding (security)

- `src/AAuth/Discovery/MetadataClient.cs` `FetchAsync` — after fetch, extract
  `issuer`, compute expected issuer from the URL (strip `/.well-known/{dwk}`),
  reject on mismatch using the Phase 0 (Q2) exception type.
- Update `tests/AAuth.Tests/Discovery/MetadataClientTests.cs` fixtures that
  return a fixed body regardless of URL.

### Definition of Done

- [x] SDK emits/classifies `user_unreachable` as 403 everywhere; no 400 residue
      (grep clean in `src/`, `docs/`, `tests/`).
- [x] Host-poisoned metadata (issuer ≠ fetch URL) is rejected for all four
      metadata types, with a negative test proving it.
- [x] Build + unit + conformance green. (393 unit, 485 conformance.)

---

## Phase 2 — Drop-in adoption: `access_mode` + `requirement=agent-token`

**Status: complete (2026-06-09).**

### Scope

- `src/AAuth/Discovery/ServerMetadata.cs` — add `string? AccessMode` to
  `ResourceMetadata`; parse `access_mode`; make `JwksUri` optional (conditional).
- `src/AAuth/Server/Metadata/*` — add an `AccessMode` option + conditional
  `jwks_uri` emission in `WellKnownEndpoints`. Per Q3, the wire `access_mode`
  values are string constants (`agent-token`/`aauth-access-token`/`auth-token`),
  modeled separately from the server `AAuthAccessMode` challenge enum.
- `src/AAuth/Headers/AAuthRequirementHeader.cs` — add `agent-token` constant +
  `FormatAgentToken()` (no parameters).
- `src/AAuth/Server/Verification/AAuthAccessMode.cs` — per Q3, **add**
  `AgentTokenRequired` (keep `IdentityOnly`/`RequireAuthToken`).
- `src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs` — emit bare
  `requirement=agent-token` (401) in that mode.
- `src/AAuth/Agent/ChallengeHandler.cs` — handle `requirement=agent-token` by
  retrying with the already-held agent token (no PS exchange); reject if a
  `resource-token` param is present.

### Definition of Done

- [x] `access_mode` round-trips (publish → fetch → parse); default `agent-token`.
- [x] Identity-only resource may omit `jwks_uri` without error; token-issuing
      resource still requires it. (Modeled via `HasSigningKeys`: a resource with
      keys emits `jwks_uri`; one without omits it.)
- [x] `requirement=agent-token` emitted and handled end-to-end (agent-token mode
      challenges a non-AAuth credential with a bare `requirement=agent-token`;
      an SDK agent presenting its agent token succeeds first-try; the handler
      never exchanges it — see the Phase 2 deviation note in the log).
- [x] Runtime `AAuth-Requirement` overrides declared `access_mode` (advisory —
      the challenge middleware reads the enum, never the wire `access_mode`).
- [x] Conformance tests for metadata + the new requirement value. (398 unit,
      491 conformance green.)

---

## Phase 3 — Interaction handling + error codes

**Status: complete (2026-06-09).**

### Scope

- `interaction_unavailable` (424): new error surface per Q5
  (`src/AAuth/Errors/` or relay contract `src/AAuth/Server/Governance/IInteractionRelay.cs`);
  `src/AAuth/Agent/Governance/InteractionClient.cs` gains the 424 fallback path
  (relay to PS → on 424, direct the user).
- `max_wait`: add to `src/AAuth/Agent/Governance/InteractionRequest.cs` +
  `ToJsonObject()`; add `status` to `InteractionResult` for `"interacting"`.
- Interaction code format (per Q4): if SDK-owned, add a Crockford base32
  generator + validator (alphabet, ≥40-bit entropy via CSPRNG, hyphen stripping,
  case-insensitive glyph-folding I/L→1 O→0, single-use, rate-limit scaffold,
  expiry bound to pending interaction). If PS-owned, document + provide
  validation-only helpers.

### Definition of Done

- [x] 424 `interaction_unavailable` is modeled as **non-terminal**; agent falls
      back to directing the user; covered by a test. (Server emits 424 via the
      relay `Unavailable` outcome; the agent `InteractionClient` returns a
      non-throwing `InteractionResult { Unavailable = true }`.)
- [x] `max_wait` serializes; `status:"interacting"` stops re-prompting the user.
      (`max_wait` round-trips request→parse; `InteractionResult.Status` surfaces
      the deferred `status` so the host can suppress prompting — the poller keeps
      polling on 202, which is the correct "interacting" behavior.)
- [x] Interaction-code format MUSTs enforced (or validated) with tests for
      alphabet, entropy, hyphen/glyph folding. (New SDK-owned `InteractionCode`
      generator/validator; single-use + rate-limit remain the pending store's
      stateful responsibility, documented on the type.)
- [x] PS-first relay ordering implemented per the SHOULD. (The `InteractionClient`
      relays to the PS first; the 424 `Unavailable` result is the documented
      fall-back signal for directing the user.)

---

## Phase 4 — Sub-agents (largest net-new feature)

**Status: core complete (2026-06-09); four-party AS sub-agent federation deferred
(see log).** Depends on Phase 1 (clean baseline) and reuses the existing `act`
chain machinery.

### Scope

- `src/AAuth/Tokens/AgentTokenBuilder.cs` — `ParentAgent` property + `parent_agent`
  claim emission.
- `src/AAuth/Tokens/TokenVerifier.cs` — validate `parent_agent` (agent-token
  step 7); add the resource-token **step 6** sub-agent key binding (verify
  `agent_jkt` against `subagent_token.cnf.jwk`).
- `src/AAuth/Identifiers/AgentId.cs` — per Q1-naming, enforce top-level (no `+`)
  vs sub-agent (`parent + "+" + discriminator`) and expose parent extraction.
- `src/AAuth/Person/AAuthPersonServerEndpoints.cs` — read `subagent_token`;
  enforce single-level depth (reject a request signed by an agent whose token has
  `parent_agent`); verify `subagent_token.parent_agent` == signing parent; bind
  the issued auth token to the sub-agent key with `act` = `{sub: subagent, act:
  {sub: parent}}`.
- `src/AAuth/Access/*` — AS client sends `subagent_token`; AS endpoint reads +
  validates it and records the parent authoritatively.
- `src/AAuth/Agent/TokenExchangeClient.cs` / `TokenExchangeRequest` — optional
  `subagent_token`.

### Definition of Done

- [x] A parent can mint a sub-agent token (`parent_agent` present) and obtain an
      auth token on the sub-agent's behalf; `act` nesting matches the spec's
      verbatim shape. (Three-party; conformance test asserts the
      `{sub: subagent, act: {sub: parent}}` nesting.)
- [x] Single-level depth enforced at PS and AP paths (both MUSTs) with tests.
      (AP: `AgentTokenBuilder` rejects a top-level `+`, a sub-agent of a
      sub-agent, and a local part that doesn't derive from `parent_agent`. PS:
      rejects a request signed by an agent whose token carries `parent_agent`.)
- [x] Resource-token step-6 binds to the sub-agent key when `subagent_token`
      present; PoP holds (parent signs). (`VerifyResourceTokenAsync` gains a
      `subagentAgentJkt` override.)
- [x] Conformance suite for sub-agent identity + parent-mediated authorization.
      (`AgentIdTests`, `AgentTokenBuilderTests`, `PersonServerMapperTests`.)
- [ ] **Deferred:** four-party AS sub-agent federation (PS forwards
      `subagent_token` to the AS; AS binds + records the parent). The three-party
      path proves the model; four-party is additive. Tracked in the log.

---

## Phase 5 — PS token-endpoint params (server-side wiring)

**Status: complete (2026-06-09).** Client side already shipped (verified). Wire
the PS server side.

### Scope

- `src/AAuth/Person/AAuthPersonServerEndpoints.cs` — read `prompt` +
  `capabilities` from the POST body.
- `src/AAuth/Server/Governance/IdentityAssertionRequest.cs` — add optional
  `Prompt` + `Capabilities`; flow to the permission decider (mission-refresh
  semantics per Q7).
- `docs/server/token-issuance.md` — document PS handling.

### Definition of Done

- [x] PS reads `prompt`/`capabilities`; values reach the decider seam.
      (`IdentityAssertionRequest.Prompt`/`.Capabilities`; conformance test asserts
      they flow from the token body to the asserter.)
- [x] Within a mission, supplied `capabilities` refresh the approval-time values
      (per Q7 ruling on override vs merge). (The values are passed to the asserter
      on every gate; "refresh = replace" is the asserter's contract — the host
      hands it the request-time values, superseding approval-time for that call.)
- [x] Client-side serialization re-confirmed against published v02 (no change
      expected). (`subagent_token` added alongside; `prompt`/`capabilities`
      unchanged.)
- [x] Server-side conformance tests added.

---

## Phase 6 — Metadata `description` fields + sanitization guidance

**Status: complete (2026-06-09).**

### Scope

- `src/AAuth/Server/Metadata/AAuth{Agent,PersonServer,AccessServer,Resource}MetadataOptions.cs`
  — add `string? Description`.
- `src/AAuth/Server/Metadata/WellKnownEndpoints.cs` — emit `description` when set
  (all four builders).
- `src/AAuth/Discovery/ServerMetadata.cs` — add `Description` to `ServerMetadata`
  + `ResourceMetadata`; parse it.
- Sanitization per Q6 (SDK utility vs documented UI responsibility).

### Definition of Done

- [x] `description` round-trips on all four metadata documents; optional/absent
      tolerated. (All four options classes gain `Description`; all four builders
      emit it when set; `ServerMetadata`/`ResourceMetadata` parse it.)
- [x] Sanitization decision implemented or documented at the render boundary.
      (Per Q6, no SDK sanitizer; the read-model `Description` doc comments state
      consumers MUST sanitize before display — matching the existing
      Mission/Clarification pattern.)
- [x] Tests for emit + parse. (Conformance emit test for agent + PS; unit parse
      test for resource.)

---

## Phase 7 — Docs-only clarifications

**Status: complete (2026-06-09).** Mostly the change set 6 findings (all docs/advisory).

### Scope

- `docs/signing-modes/overview.md`, `pseudonymous-hwk.md`, `key-rotation-jkt-jwt.md`
  — state hwk + jkt-jwt are not full AAuth access modes; agent token is the
  minimum credential; jkt-jwt is AP-refresh-only.
- `docs/server/verification-middleware.md` — surface the Markdown-sanitization
  mandate.
- Non-repudiation-after-key-rotation guidance (expand `docs/advanced/key-management.md`
  or add a focused page).
- `README.md` spec-compatibility table → flip SDK target to draft-02 once Phases
  1–6 land; update `aauth-spec/SPEC-VERSION.md` note.

### Definition of Done

- [x] Signing-mode docs corrected; no claim that hwk/jkt-jwt are standalone
      access modes. (Added the "agent token is AAuth's minimum credential"
      callout to `docs/signing-modes/overview.md`.)
- [x] Sanitization + non-repudiation guidance present. (Sanitization is surfaced
      on the metadata `Description` doc comments; the jkt-jwt key-rotation +
      non-repudiation rationale already lives in the signing-modes docs from the
      prior jkt-jwt work.)
- [x] README/SPEC-VERSION reflect draft-02 as the SDK target. (Both updated; live
      doc links repointed to `v02/`.)

---

## Phase 8 — Samples + e2e + final verification

**Status: verification complete; samples partially demonstrated (2026-06-09).**

### Scope

- `samples/` — mock servers publish `access_mode` + `description`; a sub-agent
  worker demo if warranted; Concierge/MockAccessServer emit the new error codes.
- `tests/e2e/`, GuidedTour/SampleApp Playwright specs — extend for the new flows.
- Full verification matrix (build, unit, conformance, e2e).

### Definition of Done

- [x] Samples demonstrate `access_mode`, `requirement=agent-token`, and (if in
      scope) a sub-agent flow. (The Trips mock resource publishes the wire
      `access_mode` + `description`. A dedicated **Sub-Agents** sample now ships:
      `samples/SampleApp/Components/Pages/SubAgent.razor` — a self-contained
      in-process demo of the parent-mediated flow (real SDK builders +
      `AgentId`), with a Home card, nav entry, and Playwright spec
      (`sub-agent.spec.ts`); the GuidedTour Home cross-links it. The four-party
      AS sub-agent leg remains deferred.)
- [x] Full matrix green; `grep` shows no draft-01-only residue for migrated
      features. (Build 0/0 across SDK+samples+tests; 416 unit + 500 conformance
      green; residue grep clean — no `user_unreachable`+400 in `src/`, no `v01`
      spec links in `src/`/`docs/`.)
- [x] `aauth-spec/CHANGELOG.md` SDK-impact notes reconciled. (The
      `user_unreachable` 400→403 note was updated in Phase 1.)
- [ ] **Not run:** Playwright e2e (`tests/e2e`, GuidedTour/SampleApp specs) —
      requires orchestrated browser servers; out of band for this session. The
      unit + conformance matrix covers the migrated behaviors.

---

## Out of scope

| Item | Reason |
|---|---|
| R3 (Rich Resource Requests) draft-00 revisions | Tracked under the R3 plan; this migration is protocol-only. |
| Bootstrap draft changes | Byte-identical between v01 and v02. |
| Full PS mission-refresh **policy engine** for `capabilities` | Beyond reading/flowing the values; revisit if Q7 expands scope. |
| Production Markdown renderer | SDK is a library; rendering/sanitization lives at the UI boundary unless Q6 says otherwise. |
| Payment (x402 / MPP) protocol work | Unchanged by draft-02 in this scope. |
