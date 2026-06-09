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

- [ ] **Q1** `user_unreachable` = 403 confirmed as the target (supersedes 400).
- [ ] **Q2** Metadata issuer-mismatch exception type chosen.
- [ ] **Q3** `AAuthAccessMode` additive vs rename decided.
- [ ] **Q4** Interaction-code generator/validator ownership (SDK vs PS) decided.
- [ ] **Q5** `interaction_unavailable` surface (exception vs relay outcome) decided.
- [ ] **Q6** Markdown sanitizer: SDK-integrated vs documented UI responsibility.
- [ ] **Q7** `prompt`/`capabilities` validation strictness + `provider_hint` hook.
- [ ] **Q8** Sub-agent error codes agreed.
- [ ] **Q9** No-back-compat posture confirmed for this migration.

### Definition of Done

- [ ] Each of Q1–Q9 has a recorded ruling (or an explicit "default X, revert if
      you disagree") in `implementation-log.md`.

---

## Phase 1 — Critical conformance fixes (wire mismatch + security)

Two small, high-value changes. Land first; everything else builds on a correct
baseline.

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

- [ ] SDK emits/classifies `user_unreachable` as 403 everywhere; no 400 residue
      (grep clean in `src/`, `docs/`, `tests/`).
- [ ] Host-poisoned metadata (issuer ≠ fetch URL) is rejected for all four
      metadata types, with a negative test proving it.
- [ ] Build + unit + conformance green.

---

## Phase 2 — Drop-in adoption: `access_mode` + `requirement=agent-token`

### Scope

- `src/AAuth/Discovery/ServerMetadata.cs` — add `string? AccessMode` to
  `ResourceMetadata`; parse `access_mode`; make `JwksUri` optional (conditional).
- `src/AAuth/Server/Metadata/*` — add `Description`-adjacent `AccessMode` option +
  conditional `jwks_uri` emission in `WellKnownEndpoints`.
- `src/AAuth/Headers/AAuthRequirementHeader.cs` — add `agent-token` constant +
  `FormatAgentToken()` (no parameters).
- `src/AAuth/Server/Verification/AAuthAccessMode.cs` — per Q3, add the
  agent-token-required mode.
- `src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs` — emit bare
  `requirement=agent-token` (401) in that mode.
- `src/AAuth/Agent/ChallengeHandler.cs` — handle `requirement=agent-token` by
  retrying with the already-held agent token (no PS exchange); reject if a
  `resource-token` param is present.

### Definition of Done

- [ ] `access_mode` round-trips (publish → fetch → parse); default `agent-token`.
- [ ] Identity-only resource may omit `jwks_uri` without error; token-issuing
      resource still requires it.
- [ ] `requirement=agent-token` emitted and handled end-to-end (agent retries
      with agent token, no exchange).
- [ ] Runtime `AAuth-Requirement` overrides declared `access_mode` (advisory).
- [ ] Conformance tests for metadata + the new requirement value.

---

## Phase 3 — Interaction handling + error codes

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

- [ ] 424 `interaction_unavailable` is modeled as **non-terminal**; agent falls
      back to directing the user; covered by a test.
- [ ] `max_wait` serializes; `status:"interacting"` stops re-prompting the user.
- [ ] Interaction-code format MUSTs enforced (or validated) with tests for
      alphabet, entropy, hyphen/glyph folding, single-use, rate-limit.
- [ ] PS-first relay ordering implemented per the SHOULD.

---

## Phase 4 — Sub-agents (largest net-new feature)

Depends on Phase 1 (clean baseline) and reuses the existing `act` chain
machinery.

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

- [ ] A parent can mint a sub-agent token (`parent_agent` present) and obtain an
      auth token on the sub-agent's behalf; `act` nesting matches the spec's
      verbatim shape.
- [ ] Single-level depth enforced at PS and AP paths (both MUSTs) with tests.
- [ ] Resource-token step-6 binds to the sub-agent key when `subagent_token`
      present; PoP holds (parent signs).
- [ ] Conformance suite for sub-agent identity + parent-mediated authorization.

---

## Phase 5 — PS token-endpoint params (server-side wiring)

Client side already shipped (verify only). Wire the PS server side.

### Scope

- `src/AAuth/Person/AAuthPersonServerEndpoints.cs` — read `prompt` +
  `capabilities` from the POST body.
- `src/AAuth/Server/Governance/IdentityAssertionRequest.cs` — add optional
  `Prompt` + `Capabilities`; flow to the permission decider (mission-refresh
  semantics per Q7).
- `docs/server/token-issuance.md` — document PS handling.

### Definition of Done

- [ ] PS reads `prompt`/`capabilities`; values reach the decider seam.
- [ ] Within a mission, supplied `capabilities` refresh the approval-time values
      (per Q7 ruling on override vs merge).
- [ ] Client-side serialization re-confirmed against published v02 (no change
      expected).
- [ ] Server-side conformance tests added.

---

## Phase 6 — Metadata `description` fields + sanitization guidance

### Scope

- `src/AAuth/Server/Metadata/AAuth{Agent,PersonServer,AccessServer,Resource}MetadataOptions.cs`
  — add `string? Description`.
- `src/AAuth/Server/Metadata/WellKnownEndpoints.cs` — emit `description` when set
  (all four builders).
- `src/AAuth/Discovery/ServerMetadata.cs` — add `Description` to `ServerMetadata`
  + `ResourceMetadata`; parse it.
- Sanitization per Q6 (SDK utility vs documented UI responsibility).

### Definition of Done

- [ ] `description` round-trips on all four metadata documents; optional/absent
      tolerated.
- [ ] Sanitization decision implemented or documented at the render boundary.
- [ ] Tests for emit + parse.

---

## Phase 7 — Docs-only clarifications

Mostly the change set 6 findings (all docs/advisory).

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

- [ ] Signing-mode docs corrected; no claim that hwk/jkt-jwt are standalone
      access modes.
- [ ] Sanitization + non-repudiation guidance present.
- [ ] README/SPEC-VERSION reflect draft-02 as the SDK target.

---

## Phase 8 — Samples + e2e + final verification

### Scope

- `samples/` — mock servers publish `access_mode` + `description`; a sub-agent
  worker demo if warranted; Concierge/MockAccessServer emit the new error codes.
- `tests/e2e/`, GuidedTour/SampleApp Playwright specs — extend for the new flows.
- Full verification matrix (build, unit, conformance, e2e).

### Definition of Done

- [ ] Samples demonstrate `access_mode`, `requirement=agent-token`, and (if in
      scope) a sub-agent flow.
- [ ] Full matrix green; `grep` shows no draft-01-only residue for migrated
      features.
- [ ] `aauth-spec/CHANGELOG.md` SDK-impact notes reconciled.

---

## Out of scope

| Item | Reason |
|---|---|
| R3 (Rich Resource Requests) draft-00 revisions | Tracked under the R3 plan; this migration is protocol-only. |
| Bootstrap draft changes | Byte-identical between v01 and v02. |
| Full PS mission-refresh **policy engine** for `capabilities` | Beyond reading/flowing the values; revisit if Q7 expands scope. |
| Production Markdown renderer | SDK is a library; rendering/sanitization lives at the UI boundary unless Q6 says otherwise. |
| Payment (x402 / MPP) protocol work | Unchanged by draft-02 in this scope. |
