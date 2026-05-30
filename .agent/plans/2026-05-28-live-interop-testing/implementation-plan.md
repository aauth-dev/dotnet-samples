# Live Interop Testing: Implementation Plan

> Created 2026-05-28.
> Companion to [`research.md`](./research.md).
> **Scope**: Create a live test sample against deployed servers, identify SDK gaps vs reference agent, and fix them.

---

## Gap Register

All gaps discovered during live testing against whoami.aauth.dev + person.hello.coop.
Each gap includes investigation TODOs: 1) spec accuracy, 2) SDK surfacing (opt-in/opt-out/config).

> **Updated 2026-05-30:** Spec lead confirmed Gaps A, B (prompt only), E (user_unreachable) will be standardized in -02.
> See `aauth-spec/upcoming-changes-02.md` and research.md §5b for details.

### Confirmed Fixed (spec-validated, design review pending)

| ID | Summary | Fix | Investigate Design |
|---|---|---|---|
| **A** | TokenExchangeClient doesn't send `capabilities` in POST body | `capabilities: ["interaction"]` when `onInteractionRequired` is non-null | 1) Should capabilities be a configurable list on `ChallengeHandlingOptions`? 2) Default to `["interaction"]` when handler present or require explicit opt-in? 3) Support `clarification`/`payment` capabilities? |

### Partially Fixed (pending deep analysis - approach may change)

| ID | Summary | Current Fix | Investigate Design |
|---|---|---|---|
| **G** | DeferredPoller hits HttpClient.Timeout (100s) during long-poll | Per-request CTS with PreferWait+60s; catch `TaskCanceledException` in `TokenExchangeClient` | 1) Is per-request CTS the right layer or should we fix at builder level (Gap J)? 2) Remove workaround once J is fixed? 3) Should the catch rethrow as a typed exception? |

### Open (not yet fixed)

| ID | Summary | Reference Behavior | Decision |
|---|---|---|---|
| **B** | No `prompt` in token exchange POST body | web-agent-demo sends `prompt: "consent"` | **Will fix.** `prompt` will be standard in -02 (OIDC values). `provider_hint` stays out (Hellospecific). |
| **C** | No `Accept-Signature` header parsing (adaptive signing) | whoami returns `sig=("@method" "@authority" "@path" "signature-key");sigkey=jkt` | Spec doesn't mandate agent parsing. Medium priority. |
| **D** | No built-in interaction URL opener | web-agent-demo renders UI; our callback just surfaces URL | **Won't fix.** By-design for libraries. Spec is silent. |
| **E** | PS errors thrown as generic `HttpRequestException` | PS returns `{ error, error_description }` JSON | **Will fix.** `user_unreachable` confirmed as distinct terminal error in -02. Parse JSON, typed exceptions. |
| **F** | Polling timeout defaults (MaxTotalWait=5min) untested | web-agent-demo: `POLL_WAIT_SECONDS=45`, no max budget | **Validated.** Server controls via 408. 5min client budget is a safety net. No change needed. |
| **H** | PS caches consent - no SDK cache/invalidation semantics | 2nd run got auth_token immediately (200, no interaction) | **Will fix.** Expose `prompt` option (Gap B) to allow `prompt: "consent"` for force-reconsent. |
| **I** | `content-type` not in covered components for POST | web-agent-demo signs `content-type` for body-bearing requests | **Low priority.** Spec says only `@method`, `@authority`, `@path`, `signature-key` required. Optional enhancement. |
| **J** | Exchange client HttpClient.Timeout conflicts with long-poll | Default 100s < PreferWait(45)+network latency on some cycles | **Will fix.** Set `Timeout=InfiniteTimeSpan` on exchange client in builder. Related to Gap G. |

---

## Phase 1: Sample Creation ✅

**Objective**: Create `samples/LiveWhoAmITest` demonstrating all protocol modes against live servers.

### Definition of Done

- [x] Sample builds and runs
- [x] Mode 1: No signature → 401 + `Accept-Signature`
- [x] Mode 2a: Agent token (no scope) → 200 + agent identity
- [x] Mode 2b: Agent token (scope=email) → 401 + resource_token
- [x] Mode 3: Full 3-party flow → 200 + identity claims
- [x] Parity with web-agent-demo reference agent flows

---

## Phase 2: Gap Discovery ✅

**Objective**: Run sample end-to-end, document all gaps vs reference agent.

### Definition of Done

- [x] All modes tested against live servers
- [x] Gap register populated (A–J)
- [x] Each gap has investigation TODOs

---

## Phase 3: Deep Analysis ✅

**Objective**: For each gap, determine spec accuracy and recommended SDK surfacing.

> **Completed 2026-05-30.** Spec lead clarified all open questions. Decisions recorded in Gap Register above.

### Decisions Summary

| Gap | Decision | Rationale |
|---|---|---|
| A | Confirmed correct | Spec -02 will standardize `capabilities` in body |
| B | Will fix (`prompt` only) | `prompt` going into spec -02. `provider_hint` is PS-specific, out of scope. |
| C | Defer | Spec doesn't mandate parsing. Works today. Medium priority future enhancement. |
| D | Won't fix | By-design for libraries. Consumer's responsibility. |
| E | Will fix | Parse JSON errors, typed exceptions. `user_unreachable` confirmed as distinct code. |
| F | No change needed | Validated: 5min client budget is fine, server controls via 408. |
| G | Will fix (refine) | Root cause is HttpClient.Timeout. Fix at builder level (Gap J), simplify workaround. |
| H | Will fix (via Gap B) | Expose `prompt: "consent"` to force re-consent. |
| I | Optional enhancement | Not spec-required. Low priority. |
| J | Will fix | `Timeout=InfiniteTimeSpan` on exchange HttpClient in builder. |

### Definition of Done

- [x] Each gap has a decision recorded (fix approach or "won't fix" with rationale)
- [x] Spec citations for each decision
- [x] research.md updated with findings

---

## Phase 4: Fix Implementation

**Objective**: Apply fixes per Phase 3 decisions.

### Tasks

| # | Gap | Task | File(s) |
|---|---|---|---|
| 4.1 | J/G | Set `Timeout = Timeout.InfiniteTimeSpan` on exchange HttpClient in builder | `AAuthClientBuilder.cs` |
| 4.2 | G | Simplify DeferredPoller now that HttpClient.Timeout is infinite - remove per-request CTS workaround | `DeferredPoller.cs` |
| 4.3 | B | Add `Prompt` option to `ChallengeHandlingOptions` (OIDC values: none/login/consent/select_account) | `ChallengeHandlingOptions.cs`, `TokenExchangeClient.cs` |
| 4.4 | E | Parse JSON `{ error, error_description }` on non-2xx, throw `AAuthTokenExchangeException` | `TokenExchangeClient.cs`, new exception class |
| 4.5 | E | Handle `user_unreachable` as terminal (non-retryable) vs `interaction_required` as non-terminal | `TokenExchangeClient.cs`, `DeferredPoller.cs` |
| 4.6 | A | Make `capabilities` configurable (default: `["interaction"]` when handler present, allow override) | `ChallengeHandlingOptions.cs`, `TokenExchangeClient.cs` |

### Definition of Done

- [ ] All "will fix" gaps implemented
- [ ] Unit tests for each fix
- [ ] LiveWhoAmITest passes all modes
- [ ] No regressions in existing test suite (306 tests)

---

## Phase 5: Edge Case Validation

**Objective**: Test error paths and edge cases discovered during analysis.

### Tasks

1. Test interaction timeout (user never approves)
2. Test `access_denied` (user explicitly denies)
3. Test expired/revoked agent keys
4. Test mismatched `kid` in JWKS
5. Test different scope values against whoami

### Definition of Done

- [ ] Edge cases documented in research.md
- [ ] Any new gaps added to register
- [ ] LiveWhoAmITest updated with findings

---

## Out of Scope

| Item | Reason |
|---|---|
| ECDSA / P-256 key support for live test | whoami only accepts Ed25519 |
| hwk / jkt-jwt signing modes against live servers | whoami only accepts jwt scheme |
| Multi-resource chaining | No second live resource available |
| AP enrollment against live AP | Separate initiative (`2026-05-27-ap-enrollment-key-naming`) |
| Browser-based interaction handling | Library design; consumer responsibility |
| Browser-based interaction handling | Library design; consumer responsibility |
