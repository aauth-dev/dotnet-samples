# Live Interop Testing: Implementation Plan

> Created 2026-05-28.
> Companion to [`research.md`](./research.md).
> **Scope**: Create a live test sample against deployed servers, identify SDK gaps vs reference agent, and fix them.

---

## Gap Register

All gaps discovered during live testing against whoami.aauth.dev + person.hello.coop.
Each gap includes investigation TODOs: 1) spec accuracy, 2) SDK surfacing (opt-in/opt-out/config).

### Partially Fixed (pending deep analysis — approach may change)

| ID | Summary | Current Fix | Investigate |
|---|---|---|---|
| **A** | TokenExchangeClient doesn't send `capabilities` in POST body | Added `capabilities: ["interaction"]` when `onInteractionRequired` is non-null | 1) Should capabilities be a configurable list? 2) Opt-in via `ChallengeHandlingOptions`? 3) Spec accuracy |
| **G** | DeferredPoller hits HttpClient.Timeout (100s) during long-poll → raw `TaskCanceledException` | Per-request CTS with PreferWait+60s; catch `TaskCanceledException` in `TokenExchangeClient` | 1) Set `Timeout=InfiniteTimeSpan` on exchange client instead? 2) Is wrapping TCE correct? 3) Spec silent on client timeouts |

### Open (not yet fixed)

| ID | Summary | Reference Behavior | Investigate |
|---|---|---|---|
| **B** | No `prompt` / `provider_hint` in token exchange POST body | web-agent-demo sends `prompt: "consent"`, `provider_hint: "email--"` | 1) Spec-standardized or PS-specific? 2) Opt-in on `ChallengeHandlingOptions`? |
| **C** | No `Accept-Signature` header parsing (adaptive signing) | whoami returns `sig=("@method" "@authority" "@path" "signature-key");sigkey=jkt` | 1) Spec requires agents to parse? 2) SDK auto-adapt or informational? |
| **D** | No built-in interaction URL opener | web-agent-demo renders UI; our callback just surfaces URL | 1) Spec silent. 2) Convenience helper for CLI apps? By-design for libraries? |
| **E** | PS errors thrown as generic `HttpRequestException` | PS returns `{ error, error_description }` JSON | 1) Spec defines error codes. 2) Typed exception per code? Or enriched message? |
| **F** | Polling timeout defaults (MaxTotalWait=5min) untested | web-agent-demo: `POLL_WAIT_SECONDS=45`, no max budget | 1) Spec on max total wait? 2) Is 5min too long/short? |
| **H** | PS caches consent — no SDK cache/invalidation semantics | 2nd run got auth_token immediately (200, no interaction) | 1) Spec silent on caching. 2) Expose "force consent" via `prompt=consent`? |
| **I** | `content-type` not in covered components for POST | web-agent-demo signs `content-type` for body-bearing requests | 1) Spec require `content-type` for POSTs? 2) SDK auto-include for body requests? |
| **J** | Exchange client HttpClient.Timeout conflicts with long-poll | Default 100s < PreferWait(45)+network latency on some cycles | 1) Set `Timeout=InfiniteTimeSpan`? 2) Configure in builder? (Related to Gap G) |

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

## Phase 3: Deep Analysis

**Objective**: For each gap, determine spec accuracy and recommended SDK surfacing.

### Tasks

For each gap (A–J):
1. Check AAuth spec (`draft-hardt-oauth-aauth-protocol`) for relevant requirements
2. Check reference implementations (web-agent-demo, aauth-go-library, aauth-python-library)
3. Decide: opt-in config, opt-out config, always-on, or out-of-scope
4. Document decision in this plan

### Definition of Done

- [ ] Each gap has a decision recorded (fix approach or "won't fix" with rationale)
- [ ] Spec citations for each decision
- [ ] research.md updated with findings

---

## Phase 4: Fix Implementation

**Objective**: Apply fixes per Phase 3 decisions.

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
